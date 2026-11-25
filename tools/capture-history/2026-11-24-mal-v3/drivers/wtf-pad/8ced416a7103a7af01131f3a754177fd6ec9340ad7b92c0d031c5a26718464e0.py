#!/usr/bin/env python3
"""Isolated class-replacement owner; source and upload remain independently gated."""
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

def assert_no_pilot_worker(pilot_dir):
 proc_root=pathlib.Path('/proc')
 if not proc_root.is_dir():raise RuntimeError('cannot inspect pilot processes')
 for proc in proc_root.iterdir():
  if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
  try:args=(proc/'cmdline').read_bytes().split(b'\0')
  except (FileNotFoundError,ProcessLookupError):continue
  if any(str(pilot_dir).encode() in a for a in args) and any(b'tcpdump' in a or b'neqo-qcsd-client' in a or a.endswith(b'/client') for a in args):raise RuntimeError('pilot worker still active')

def verify_class_pilot():
 report_path=pathlib.Path(CONFIG['pilot_report']);domain_root=pathlib.Path(CONFIG['domain_root'])
 if report_path.name!='RESULT.json' or not report_path.parent.resolve().is_relative_to(domain_root.resolve()) or report_path.parent.is_symlink():raise ValueError('pilot outside class scope')
 report=json.loads(stable_read(report_path,CONFIG['class_pilot_report_sha256']))
 if report.get('host')!=HOST or report.get('purpose')!='no-credit 20-resource defended pilot' or report.get('production_slot') is not None or report.get('pilot_pass') is not True or report.get('exit_code')!=0 or report.get('error') or report.get('successful_responses')!=20:raise ValueError('no eligible no-credit pilot')
 if (report.get('capture_counts') or {}).get('dropped')!=0 or type((report.get('capture_counts') or {}).get('captured')) is not int or report['capture_counts']['captured']<=0 or report['capture_counts']['captured']!=report['capture_counts'].get('received') or type(report.get('filtered_packets')) is not int or report['filtered_packets']<=0:raise ValueError('pilot packet loss')
 native=report_path.parent/'stage/native/run.json';pcap=report_path.parent/'capture-isolated.pcap'
 assert_no_pilot_worker(report_path.parent)
 run=json.loads(stable_read(native,report['native_sha256']));stable_read(pcap,report['isolated_sha256'])
 resources=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json']))['resources'];wanted={(x['id'],x['url']) for x in resources}
 responses=run.get('responses') or [];passed=[(x.get('resource_id'),x.get('url')) for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
 endpoints=run.get('endpoints') or [];cfg=run.get('resolved_configuration') or {};params=run.get('defense_parameters') or {};diag=run.get('defense_diagnostics') or {}
 if not (len(resources)==20 and len(wanted)==20 and len(responses)==20 and len(passed)==20 and set(passed)==wanted and len(endpoints)==1 and endpoints[0].get('origin')=='https://'+HOST+'/' and endpoints[0].get('negotiated_protocol')=='h3' and run.get('completion_status')=='complete' and not run.get('error') and cfg.get('defense',{}).get('kind')=='wtf_pad' and params.get('kind')=='wtf_pad' and params.get('sha256')==MODEL_SHA and diag.get('padding_event_guard_triggered') is False and run.get('workload_hash_sha256')==INPUT_SHA['resources.json'] and run.get('application_workload_source_hash_sha256')==INPUT_SHA['prepared-workload.json'] and run.get('chaff_manifest_hash_sha256')==INPUT_SHA['chaff-manifest.json']):raise ValueError('pilot native evidence mismatch')

def predecessor_proof_with_retry(helper):
 last=None
 for n in range(3):
  try:return json.loads(command(['/usr/bin/python3',str(helper),'--hostname',HOST],timeout=45))
  except subprocess.CalledProcessError as e:last=e
  except subprocess.TimeoutExpired as e:last=e
  if n<2:time.sleep(2**n)
 raise RuntimeError('predecessor proof unavailable after bounded transient retries') from last

NETWORK_SHA='459c40399147b6b884dfd8c6b42bf6833280be182d1247cafbc0e9e58d490058'
HISTORY_PIN='1ae0de8beab30ad40ef4464b7f1935bbcb68894463102f07a1697d2c2666b63c'
NOTE_PIN='bd7fbaa0eddeec4c613e3bdc756d1d60438229cbc5bca1c752d0600328f28995'
RESOURCE_PIN='eefdae5a1e95620cb1f75a334ca3531ef64669b0f8e6bed7d6449f2b2ae28c22'
NETWORK_MODULE_SHA='c510863d444a03ba1e46f44f93bfed330cffa0077cdea38fb377069b73638407'

def verify_transfer(expected_container=None):
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(pathlib.Path(__file__))!=CONFIG['owner_sha256'] or sha(HISTORY)!=HISTORY_PIN:raise RuntimeError('cohort owner/config/history changed')
 if sha(pathlib.Path(CONFIG['base_config']))!=CONFIG['base_config_sha256'] or CONFIG['base_config_sha256']!='f059b283893574233bb73855fbbf1b0852d04ff83970d090087bffd52c35ba4e':raise RuntimeError('base configuration changed')
 if sha(NOTE)!=NOTE_PIN or INPUT_SHA['resources.json']!=RESOURCE_PIN:raise ValueError('v3 roster pin changed')
 note=json.loads(stable_read(NOTE,NOTE_PIN))
 if note.get('kind')!='mal-roster-v3-resource-replacement-note' or note.get('domain')!=HOST or [c.get('resource_id') for c in note.get('changes',[])]!=[18]:raise ValueError('v3 replacement note changed')
 history=json.loads(stable_read(HISTORY,HISTORY_PIN))
 if history.get('kind')!='mal-roster-v3-prior-tuple-history' or history.get('domain')!=HOST or history.get('imported_as_v3_sessions') is not False:raise ValueError('prior tuple history mismatch')
 network=WORKER_SPECS[WORKER_INDEX]
 WORKER_POLICY.read_network(network,expected_container);WORKER_POLICY.disjoint(history,network)
 if sha(pathlib.Path(CONFIG['pilot_report']))!=CONFIG['class_pilot_report_sha256']:raise ValueError('pilot changed')
 reserved=set(history.get('reserved_native_tuples',[]))
 for item in history.get('committed',[]):reserved.update(item.get('native_tuple_keys',[]))
 pilot_run=json.loads(stable_read(pathlib.Path(CONFIG['pilot_report']).parent/'stage/native/run.json',CONFIG['pilot_native_sha256']))
 reserved.update(tuple_keys(pilot_run))
 if not reserved:raise ValueError('missing prior tuple exclusions')
 return {'entries':[],'reserved_native_tuples':sorted(reserved)}

def worker_ip(container):
 return WORKER_POLICY.inspect_container(WORKER_SPECS[WORKER_INDEX],container)

def initialize_ledger(history,cutover_sha):
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['domain_root'])/'shared_ledger.py',CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode='wtfpad',config_sha=CONFIG['base_config_sha256'],prepared_sha=INPUT_SHA['prepared-workload.json'])
 for slot,aid,digest in LEDGER.committed(db,'wtfpad'):
  p=ROOT/'attempts'/HOST/aid/'FINAL.json';record=json.loads(stable_read(p,digest))
  if record.get('slot')!=slot or record.get('status')!='success':raise RuntimeError('ledger FINAL mismatch')
  actual=tuple_keys(json.loads(stable_read(p.parent/'native/run.json',record['files']['native/run.json']['sha256'])))
  rows=[x[0] for x in db.execute("SELECT k FROM tuples WHERE mode='wtfpad' AND attempt=? AND slot=? AND final_sha=? AND state='committed'",(aid,slot,digest))]
  if set(actual)!=set(rows):raise RuntimeError('committed tuples differ')
 for p in (ROOT/'attempts'/HOST).glob('*'):
  if p.is_symlink() or not p.is_dir() or not (p/'FINAL.json').is_file():raise RuntimeError('unsealed attempt needs reconciliation')
  record=json.loads(stable_read(p/'FINAL.json'))
  if record.get('attempt_id')!=p.name or record.get('hostname')!=HOST:raise RuntimeError('attempt identity mismatch')
  if record.get('status')=='success' and db.execute("SELECT attempt FROM sessions WHERE mode='wtfpad' AND slot=?",(record['slot'],)).fetchone()!=(p.name,):raise RuntimeError('untracked success')
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
 network=ipaddress.ip_network(WORKER_SPECS[WORKER_INDEX]['subnet']);used=set()
 for intent in (ROOT/'parallel-journals').glob('*/*/INTENT.json'):
  record=json.loads(stable_read(intent));args=record.get('args')
  if not isinstance(args,list) or args.count('--ip')!=1:raise RuntimeError('unsafe prior worker IP journal')
  ip=ipaddress.ip_address(args[args.index('--ip')+1])
  if ip in network:used.add(str(ip))
 desired_ip=next((str(network.network_address+n) for n in range(10,255) if str(network.network_address+n) not in used),None)
 if desired_ip is None:raise RuntimeError('fresh worker IP allocation exhausted')
 args=['docker','run','-d','--network',WORKER_SPECS[WORKER_INDEX]['id'],'--ip',desired_ip,'--label','qcsd.owner='+LABEL,'--label','qcsd.parallel-scope=mal-v3-wtfpad-001',
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
def attempt(container,stage,db,slot,isolation,cutover_sha,lease_token,aid):
 baseline=verify_transfer(container)
 expected_ip=worker_ip(container)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir();raw=directory/'capture.pcap'
 spool_root=pathlib.Path('/dev/shm/qcsd-mal-v3-wtfpad-tmpfs-001');spool_root.mkdir(mode=0o700,exist_ok=True)
 if spool_root.is_symlink() or not spool_root.is_dir() or shutil.disk_usage(spool_root).free<512*1024**2:raise RuntimeError('unsafe or full tmpfs spool')
 memline=next((line for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')),None)
 if memline is None or int(memline.split()[1])*1024<1536*1024**2:raise RuntimeError('insufficient available memory for bounded tmpfs spool')
 if not any(line.split()[1:3]==['/dev/shm','tmpfs'] for line in pathlib.Path('/proc/mounts').read_text().splitlines()):raise RuntimeError('expected tmpfs mount missing')
 spool_dir=spool_root/aid;spool_dir.mkdir(mode=0o700);spool_raw=spool_dir/'capture.pcap'
 lock=(directory/'attempt.lock').open('x')
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
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
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json',
    '--chaff-manifest','/inputs/chaff-manifest.json','--profile','research-1200','--defense','wtf-pad','--wtf-pad-histograms','/model.json',
    '--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds','60']
   with (directory/'invocation.json').open('x') as f:json.dump({'argv':argv,'container':container,'seed':seed},f);f.write('\n');f.flush();os.fsync(f.fileno())
   with (directory/'client.log').open('xb') as f:
    exec_begun=True
    code=subprocess.run(['docker','exec',container,*argv],stdout=f,stderr=subprocess.STDOUT,timeout=90).returncode
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
   if spool_raw.exists():
    chmod_capture_with_retry(spool_raw)
    if observer and observer.poll() is None:raise RuntimeError('collector remains alive; preserve guest spool')
    shutil.copyfile(spool_raw,raw)
    if sha(raw)!=sha(spool_raw):raise RuntimeError('guest spool copy differs; preserve source')
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
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  active=(run.get('resolved_configuration',{}).get('defense',{}).get('kind')=='wtf_pad'
    and run.get('resolved_configuration',{}).get('max_chaff_streams')==5
    and type(run.get('defense_start_monotonic_ns')) is int and run['defense_start_monotonic_ns']>0
    and (run.get('defense_parameters') or {}).get('kind')=='wtf_pad' and (run.get('defense_parameters') or {}).get('sha256')==MODEL_SHA and run.get('workload_hash_sha256')==INPUT_SHA['resources.json'] and run.get('application_workload_source_hash_sha256')==INPUT_SHA['prepared-workload.json']
    and run.get('chaff_manifest_hash_sha256')==INPUT_SHA['chaff-manifest.json'])
  chaff=run.get('chaff_responses')
  chaff_clean,incomplete=clean_chaff(chaff)
  chaff_errors=sum(not chaff_entry_clean(c) for c in chaff) if type(chaff) is list else None
  max_chaff=run.get('resolved_configuration',{}).get('max_chaff_streams')
  diag=run.get('defense_diagnostics') or {};guard=diag.get('padding_event_guard_triggered');padding=diag.get('padding_events')
  retirement=[];tail_ok=False;shortfall=diag.get('wtf_pad_incoming_shortfall_bytes');retired_bytes=diag.get('scheduled_incoming_retired_bytes')
  try:
   with (directory/'native/events.csv').open(newline='') as f:
    for event in csv.DictReader(f):
     if event.get('event')=='wtf_pad_experimental_tiny_tail':retirement.append(json.loads(event['details']))
   tail_ok=quiet_tail_screen(diag,retirement)
  except (OSError,ValueError,KeyError,TypeError):tail_ok=False
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  local_ips={socket_address(e['tuple']['local'])[0] for e in (run.get('endpoints') or [])};network_ip_ok=(local_ips=={expected_ip} and worker_ip(container)==expected_ip)
  clean=(network_ip_ok and code==0 and not error and run.get('completion_status')=='complete' and not run.get('error') and not run.get('error_class') and h3_valid(run,HOST) and len(responses)==len(passed)==20
    and {x.get('resource_id') for x in passed}==set(range(20)) and roster_ok and active and chaff_clean and guard is False and type(padding) is int and padding>=0 and tail_ok and cap_ok)
  keys=[];collision=[]
  if cap_ok and isinstance(run.get('endpoints'),list) and run.get('endpoints'):
   keys=tuple_keys(run)
  if clean:
   try:LEASES.reserve(db,slot,lease_token,aid,keys,set(baseline['reserved_native_tuples']))
   except ValueError as exc:raise RuntimeError('tuple/slot conflict; preserve attempt unsealed') from exc
  elif not cap_ok or not keys:
   raise RuntimeError('partial capture lacks complete endpoint evidence; preserve unsealed attempt')
  files={}
  for p in sorted(directory.rglob('*')):
   if p.is_file() and p.name not in ('FINAL.json','attempt.lock','.FINAL.tmp'):files[str(p.relative_to(directory))]={'sha256':sha(p),'size':p.stat().st_size}
  previous=[]
  for p in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
   old_bytes=stable_read(p);old=json.loads(old_bytes)
   if old.get('slot')==slot and old.get('status')!='success':previous.append({'attempt_id':old['attempt_id'],'final_sha256':hashlib.sha256(old_bytes).hexdigest()})
  previous.extend({'attempt_id':r['attempt_id'],'final_sha256':r['final_sha256']} for r in baseline['entries'] if r['slot']==slot and r['status']!='success')
  supersedes=[]
  final={'schema_version':1,'hostname':HOST,'attempt_id':aid,'slot':slot,'purpose':'production','defense':'wtf-pad',
   'status':'success' if clean else 'partial','successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'padding_event_guard_triggered':guard,'padding_events':padding,'zero_padding_observed':padding==0,
   'model_sha256':MODEL_SHA,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),
   'tuple_verifier_sha256':MODULE_SHA,'capture_policy':'durable-buffered-nonpromiscuous-exact-isolation-v1','runtime_condition':'schema3-4-response-only-wtf-pad-5ms-handoff-grace-delay-edges-100x-tiny-tail-quiet2s-replacement-v1',
   'guest_spool_path':str(spool_raw),'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'chaff_clean_screen':chaff_clean,'incomplete_chaff_indices':incomplete,'configured_max_chaff_streams':max_chaff,'terminal_incomplete_chaff_count':len(incomplete) if type(chaff) is list else None,'explicit_chaff_errors':chaff_errors,'native_tuple_keys':keys,'tuple_collisions':collision,
   'source_role':'wtfpad-mal-roster-v3-20261124','replacement_cohort':'mal-roster-v3-001','owner_sha256':sha(pathlib.Path(__file__)),'replacement_note_sha256':NOTE_PIN,'workload_sha256':INPUT_SHA['resources.json'],'pilot_report_sha256':CONFIG['class_pilot_report_sha256'],'network_manifest_sha256':NETWORK_SHA,'worker_manifest_sha256':CONFIG['worker_manifest_sha256'],'worker_network_id':WORKER_SPECS[WORKER_INDEX]['id'],'worker_network_subnet':WORKER_SPECS[WORKER_INDEX]['subnet'],'worker_ip':expected_ip,'history_sha256':CONFIG['history_sha256'],'ownership_sha256':CONFIG_SHA,'prior_history_sha256':AUDIT_SHA,'supersedes_attempt_ids':supersedes,'prior_nonclean_attempts':previous,'prior_unsealed_attempts':CONFIG['prior_unsealed_attempts'],'tiny_tail_policy':{'maximum_retired_bytes':8,'minimum_quiet_us':2000000,'shortfall_bytes':shortfall,'retired_bytes':retired_bytes,'events':retirement,'screen_passed':tail_ok},'mode_evidence':'native/run.json','files':files}
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  finalsha=store_final(directory,final)
  if clean:
   LEASES.commit(db,slot,lease_token,aid,finalsha)
  else:
   journal=ROOT/'parallel-recovery-journals';journal.mkdir(parents=True,exist_ok=True)
   audit=journal/(aid+'.json');write_record(audit,{'kind':'wtfpad-partial-lease-release','slot':slot,'attempt':aid,'token':lease_token,'final_sha256':finalsha,'keys':keys,'capture_credit':False})
   LEASES.exclude_and_release(db,slot,lease_token,aid,keys,finalsha,str(audit.resolve()),sha(audit),set(baseline['reserved_native_tuples']))
  # Remove only this attempt's transient duplicate after a durable FINAL, ledger
  # transaction and fresh byte-for-byte hash comparison. Incomplete captures are
  # intentionally left untouched for investigation.
  try:
   if cap_ok and spool_raw.parent.parent==spool_root and spool_raw.name=='capture.pcap' and not spool_raw.is_symlink() and not raw.is_symlink() and spool_raw.is_file() and raw.is_file() and sha(spool_raw)==sha(raw):
    spool_raw.unlink();spool_raw.parent.rmdir()
  except OSError as exc:
   print(json.dumps({'event':'tmpfs-duplicate-retained','attempt_id':aid,'reason':repr(exc)}),flush=True)
  print(json.dumps({'hostname':HOST,'slot':slot,'status':final['status'],'attempt_id':aid,'directory':str(directory)},sort_keys=True),flush=True)
  return final['status'],cap_ok,retire
 finally:
  lock.close()

def verify_parallel_journals():
 path=ROOT/'parallel-journals'
 if not path.exists():return
 for worker in path.iterdir():
  if worker.is_symlink() or not worker.is_dir():raise RuntimeError('unsafe parallel journal')
  for entry in worker.iterdir():
   if entry.is_symlink() or not entry.is_dir() or any(not (entry/name).is_file() for name in ('INTENT.json','RESULT.json','RESOLVED.json')):raise RuntimeError('unresolved parallel container creation')

def worker(index,once,stopping):
 global WORKER_INDEX,LABEL,CREATE_JOURNAL
 WORKER_INDEX=index;token=secrets.token_hex(16);LABEL='qcsd-mal-v3-wtfpad-parallel-'+token
 CREATE_JOURNAL=ROOT/'parallel-journals'/token;CREATE_JOURNAL.mkdir(parents=True,exist_ok=False);sync_dir(CREATE_JOURNAL.parent)
 db=sqlite3.connect(TUPLE_DB,timeout=30,isolation_level=None);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=30000');LEASES.validate(db)
 stage=ROOT/('worker-stage-parallel-'+token);stage.mkdir();sync_dir(ROOT);container=None;failures=0
 try:
  container=start_container(stage)
  while not stopping.is_set() and failures<6:
   aid=secrets.token_hex(16);lease_token=secrets.token_hex(16);slot=LEASES.claim(db,lease_token,aid)
   if slot is None:break
   status,screen,retired=attempt(container,stage,db,slot,ISOLATION,CONFIG['history_sha256'],lease_token,aid)
   if retired:container=None
   failures=0 if status=='success' else failures+1
   if once or stopping.wait(2):break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  db.close()

def main():
 import multiprocessing
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,LEASES,ISOLATION,WORKER_INDEX,WORKER_POLICY,WORKER_SPECS
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--once',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module']);AUDIT=pathlib.Path(CONFIG['quarantine'])
 IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];AUDIT_SHA=CONFIG['quarantine_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=pathlib.Path(CONFIG['ledger_path']);CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-mal-v3-wtfpad-parallel-supervisor'
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001/cdn.myanimelist.net-roster-v3-001')
 if HOST!='cdn.myanimelist.net' or ROOT!=domain_root/'modes/wtfpad' or INPUTS!=domain_root/'inputs' or NOTE!=INPUTS/'replacement-note.json' or TUPLE_DB!=domain_root/'shared-ledger-v3.sqlite3':raise ValueError('v3 parallel scope mismatch')
 if CONFIG['exclusive_fence_locks']!=[] or ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS or CONFIG.get('workers')!=3:raise ValueError('unsafe scope')
 if sha(pathlib.Path(CONFIG['prior_config']))!=CONFIG['prior_config_sha256'] or CONFIG['prior_config_sha256']!='5d961bd8d58aa66dc41f90ad9ea38778030398a62f9c39d0e93459430ad24115':raise ValueError('prior configuration changed')
 lock=(ROOT/'production-owner.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 WORKER_POLICY=load_pinned_module(pathlib.Path(CONFIG['worker_policy']),CONFIG['worker_policy_sha256'])
 manifest=json.loads(stable_read(pathlib.Path(CONFIG['worker_manifest']),CONFIG['worker_manifest_sha256']))
 WORKER_SPECS=manifest['networks']
 if len(WORKER_SPECS)!=3 or [x['index'] for x in WORKER_SPECS]!=[0,1,2]:raise ValueError('worker manifest mismatch')
 history=json.loads(stable_read(HISTORY,HISTORY_PIN))
 for spec in WORKER_SPECS:WORKER_POLICY.read_network(spec,None);WORKER_POLICY.disjoint(history,spec)
 WORKER_INDEX=0;baseline=verify_transfer();verify_class_pilot()
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image changed')
 reconcile_creation_journal();verify_parallel_journals()
 if command(['docker','ps','-aq','--filter','label=qcsd.parallel-scope=mal-v3-wtfpad-001']):raise RuntimeError('previous parallel worker present')
 ISOLATION=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 LEASES=load_pinned_module(pathlib.Path(CONFIG['leases_module']),CONFIG['leases_module_sha256']);LEASES.initialize(db)
 if db.execute("select 1 from slot_leases where mode='wtfpad' and state!='complete' limit 1").fetchone():raise RuntimeError('unfinished WTF-PAD lease requires reconciliation')
 db.close();ctx=multiprocessing.get_context('fork');stopping=ctx.Event();children=[]
 signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set())
 try:
  for i in range(CONFIG['workers']):
   child=ctx.Process(target=worker,args=(i,args.once,stopping));child.start();children.append(child)
  for child in children:child.join()
 finally:
  for child in children:
   if child.is_alive():child.join()
 if any(child.exitcode!=0 for child in children):raise RuntimeError('parallel worker failed; preserve leases')
 print(json.dumps({'mode':'wtfpad','workers':len(children),'status':'workers-exited'}),flush=True)
if __name__=='__main__':main()
