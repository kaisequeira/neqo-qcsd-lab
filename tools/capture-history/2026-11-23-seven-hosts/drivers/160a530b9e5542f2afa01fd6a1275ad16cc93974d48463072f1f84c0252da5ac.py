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
 if mode!='cs-buflo' or not isinstance(run,dict) or run.get('request_policy')!='half-duplex' or not isinstance(roster,list) or len(roster)!=20:return False
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

OLD_CONFIG_SHA='77b48307507909c1322f58367de1c34b3ae729289b6c12141f5118d07e5086cc'
VARIATION_SHA='815697e7832909e52e6dd45f8c3d8385eb69e18da4cd760fbdd18fe0c86834f5'
PARTIAL_ID='0f621e96d32e0c1fd755f01fed80ecf2'
PARTIAL_FINAL='a60faf4a594f68284ef4c91dc17e0ac2a51a689a762185ca3cd17bf728e95b3a'
PARTIAL_AUDIT='b03ebb5993854d3252be6348bd107210cba2dc00d40f0226549ffa9ef16e404d'
PARTIAL_KEY='["udp","172.29.172.2",52857,"104.16.179.112",443]'
SECOND_ID='ec3dbee367e4a4750948abadacb7a6c0'
SECOND_FINAL='5ae8d27214dc94858db0d3782db14f1f0a94668bdb3aa898f2d953ff6ca5633c'
SECOND_AUDIT='ca681d504eb413d950db54d552c25d54cade7d65bb7d0a0b48c9154ebed2584f'
SECOND_KEY='["udp","172.29.172.2",42762,"104.16.179.112",443]'
THIRD_ID='f519226cbea41d4609cee1f6bcf7866d'
THIRD_FINAL='8b67642c99f51e8471b538d08e6d29f6cdb5538a1fbfeb297590ee9ab1705c32'
THIRD_AUDIT='9d30afd259a11b8d7d76b002c3865596046de2e160059dfbc1a92aa39dc23f99'
THIRD_KEY='["udp","172.29.172.2",55549,"151.101.129.229",443]'
FOURTH_ID='34529bc700bae775b8cb867809109dfd'
FOURTH_FINAL='1d9b0b96a6551bc3a38eb4e6e018ffbb54b1cf00cc45580924cb9891663d7d74'
FOURTH_AUDIT='f8b5701d724129207533a62219febe5c85d170856d66649d576c2766c6167a24'
FOURTH_KEY='["udp","172.29.172.2",44468,"151.101.129.229",443]'
FIFTH_ID='f168360e4246b4cc95a20429e0532c47'
FIFTH_FINAL='cb4d15562ac2b62d6fab5a95f151ad9a87cffa7f5da6308908ca62c255608dc7'
FIFTH_AUDIT='a10611f6018dde2bc123357a8cfe4f6aec6b1f161da07d6c1fee5ce35e4f0833'
FIFTH_KEY='["udp","172.29.172.2",45792,"151.101.193.229",443]'
SIXTH_ID='a2a30d4fcfb5e0015abd4a066347bc1a'
SIXTH_FINAL='4027910f81ccbc137559f92e841727bfb20b3412ad0ca03d40f9c2f9dba38f64'
SIXTH_AUDIT='cecc4ace97b50bb65639d0cdafe75c8dd704453194dba1bb6a91919795b18aff'
SIXTH_KEY='["udp","172.29.172.2",56949,"151.101.129.229",443]'
PRIORITY_NOTE_SHA='cfb7de21773b755e2fc8cb0230c25749e76c965232cae1f3dcc9b5b7f75ab903'

def priority_wrapper(argv):
 gate='test "$(/usr/bin/awk \'{print $19}\' /proc/self/stat)" = -10 || exit 120; exec "$@"'
 return ['/usr/bin/nice','-n','-10','/bin/sh','-c',gate,'verified-nice',*argv]


def validate_successor_config(new,old):
 allowed={'owner_sha256','inputs','input_sha256','ledger_config_sha256'}
 if {k:v for k,v in new.items() if k not in allowed}!={k:v for k,v in old.items() if k not in allowed}:raise ValueError('unrelated settings changed')
 for k in ('resources.json','prepared-workload.json'):
  if new['input_sha256'].get(k)!=old['input_sha256'].get(k):raise ValueError('fixed workload changed')
 if set(new['input_sha256'])!={'resources.json','prepared-workload.json','chaff-manifest.json','params/cs-buflo.json','params/custom-receive.toml'} or new['input_sha256']['params/cs-buflo.json']!='ec2ed0107f604bb6fdaad5bb8f1ace28f1d4ac26b358017de78b2f0a9b5a6b42' or new['input_sha256']['params/custom-receive.toml']!='0ea8e15cbb579901a2325b9fc72d1d7fbe63445642e044aaaeebbcf8cbf8511d':raise ValueError('unapproved parameters')

 if new['input_sha256'].get('chaff-manifest.json')!='6cd5fed0318a41a05890325eb4be5864fb5f1a522163be5b60d1b6464ec560a4':raise ValueError('unqualified chaff')

CONTROL_VARIATION_SHA='fabb77684889cbee5ce1f508111ca7298cdceee3c5d5c9fa6c205b3c1b66e919'
DIAGNOSTIC_RUN_SHA='169d542e31c65f155969907cd0f360b3f7e80a97656b870d931285d96736b274'
DIAGNOSTIC_RESULT_SHA='782eefa78742a65bc4a1075a69e61fbb2c0bd4e842bb5b553177227f3a61a038'
DIAGNOSTIC_EVENTS_SHA='68a566bd6906532ae07d4a41b7535cc5e2ea15e6baab57a4bad430976790c77f'
def verify_control_diagnostic():
 n=json.loads(stable_read(ROOT/'controller-interval-variation-001.json',CONTROL_VARIATION_SHA));base=ROOT.parent.parent/'diagnostic-cs-control10ms-long-run-001';report=json.loads(stable_read(base/'diagnostic-result.json',DIAGNOSTIC_RESULT_SHA));run=json.loads(stable_read(base/'native/run.json',DIAGNOSTIC_RUN_SHA));roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json']))['resources']
 if n.get('kind')!='cs-buflo-controller-interval-variation' or n.get('domain')!=HOST or n.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or n.get('application_urls_changed') is not False or n.get('control_interval_us')!=10000 or n.get('previous_control_interval_us')!=5000 or n.get('cs_parameters_sha256')!=INPUT_SHA['params/cs-buflo.json'] or n.get('receive_config_sha256')!=INPUT_SHA['params/custom-receive.toml'] or n.get('request_policy')!='half-duplex' or n.get('diagnostic_native_sha256')!=DIAGNOSTIC_RUN_SHA or n.get('diagnostic_events_sha256')!=DIAGNOSTIC_EVENTS_SHA or n.get('diagnostic_result_sha256')!=DIAGNOSTIC_RESULT_SHA or n.get('diagnostic_capture_credit') is not False:raise ValueError('controller timing note changed')
 if report.get('kind')!='jsdelivr-cs-control10ms-long-no-credit-diagnostic' or report.get('capture_credit') is not False or report.get('packet_capture_performed') is not False or report.get('process_exit_code')!=0 or report.get('outer_timeout') is not False or report.get('workload_sha256')!=INPUT_SHA['resources.json'] or report.get('config_sha256')!=INPUT_SHA['params/custom-receive.toml']:raise ValueError('no-credit diagnostic changed')
 cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {};expected={'schema_version':2,'control_interval_us':10000,'initial_max_stream_data':8192,'automatic_receive_window':1048576,'max_chaff_streams':5,'low_watermark':1000000,'use_empty_resources':False,'max_stream_data_excess':1000,'max_udp_payload_size':1200,'drop_unsatisfied_events':False,'keep_alive_lead_time_us':100000,'tail_wait_us':0,'defense':{'kind':'cs_buflo','parameters':'/inputs/params/cs-buflo.json'}}
 if cfg!=expected or not defended_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json'],INPUT_SHA['chaff-manifest.json'],'cs-buflo',INPUT_SHA['params/cs-buflo.json']) or diag.get('cs_buflo_scheduled_outgoing_cells',0)<=0 or diag.get('cs_buflo_scheduled_incoming_cells',0)<=0 or diag.get('cs_buflo_missed_outgoing_cells')!=0 or diag.get('cs_buflo_missed_incoming_cells')!=0:raise ValueError('no-credit CS diagnostic did not pass')
 keys=tuple_keys(run)
 if keys!=[n.get('diagnostic_endpoint')]:raise ValueError('diagnostic endpoint changed')
 if ipaddress.ip_address(json.loads(keys[0])[1]) in ipaddress.ip_network(CONFIG['network']['subnet']):raise ValueError('diagnostic and production subnet overlap')

def verify_transfer(expected_container=None):
 if MODE!='cs-buflo' or sha(ROOT/'owner-config-001.json')!=OLD_CONFIG_SHA or CONFIG.get('ledger_config_sha256')!=OLD_CONFIG_SHA:raise ValueError('original ledger configuration changed')
 old=json.loads(stable_read(ROOT/'owner-config-001.json',OLD_CONFIG_SHA));validate_successor_config(CONFIG,old)
 fit=ROOT.parent.parent/'tamaraw-larger-chaff-fit-001'; evidence=json.loads(stable_read(fit/'qualification-evidence.json','57714a50604221cc1f01c7c779dd9ffd69e1b74daff2c45c65344ef2c5ba5b67'))
 if evidence.get('status')!='THREE_INDEPENDENT_40_RESPONSE_EPOCHS' or evidence.get('domain')!=HOST or evidence.get('resource_id')!=2 or evidence.get('prepared_sha256')!=INPUT_SHA['prepared-workload.json'] or len(evidence.get('epochs',[]))!=3:raise ValueError('chaff qualification changed')
 for n,epoch in enumerate(evidence['epochs']):
  path=fit/('epoch-'+str(n))/'qualification.json'
  if epoch.get('epoch')!=n or epoch.get('responses')!=40 or epoch.get('qualification_path')!=str(path):raise ValueError('invalid qualification epoch')
  report=json.loads(stable_read(path,epoch['sha256']))
  if report.get('passed') is not True or report.get('completion_status')!='complete' or report.get('total_requests')!=40 or len(report.get('requests',[]))!=40:raise ValueError('chaff qualification failed')
 priority=json.loads(stable_read(ROOT/'priority-variation-001.json',PRIORITY_NOTE_SHA))
 if priority.get('kind')!='cs-buflo-scheduling-priority-variation' or priority.get('domain')!=HOST or priority.get('niceness')!=-10 or priority.get('policy')!='SCHED_OTHER' or priority.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or priority.get('application_urls_changed') is not False:raise ValueError('priority note changed')
 note=json.loads(stable_read(ROOT/'realization-variation-002.json',VARIATION_SHA))
 if note.get('kind')!='cs-buflo-documented-realization-variation' or note.get('domain')!=HOST or note.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or note.get('application_urls_changed') is not False or note.get('request_policy')!='half-duplex':raise ValueError('realization variation changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+PARTIAL_ID+'.json'),PARTIAL_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=PARTIAL_ID or audit.get('final_sha256')!=PARTIAL_FINAL or audit.get('native_tuple_keys')!=[PARTIAL_KEY] or audit.get('raw_pcap_tuple_keys')!=[PARTIAL_KEY] or sha(ROOT/'attempts'/HOST/PARTIAL_ID/'FINAL.json')!=PARTIAL_FINAL:raise ValueError('partial audit changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+SECOND_ID+'.json'),SECOND_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=SECOND_ID or audit.get('final_sha256')!=SECOND_FINAL or audit.get('native_tuple_keys')!=[SECOND_KEY] or audit.get('raw_pcap_tuple_keys')!=[SECOND_KEY] or sha(ROOT/'attempts'/HOST/SECOND_ID/'FINAL.json')!=SECOND_FINAL:raise ValueError('second partial audit changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+THIRD_ID+'.json'),THIRD_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=THIRD_ID or audit.get('final_sha256')!=THIRD_FINAL or audit.get('native_tuple_keys')!=[THIRD_KEY] or audit.get('raw_pcap_tuple_keys')!=[THIRD_KEY] or sha(ROOT/'attempts'/HOST/THIRD_ID/'FINAL.json')!=THIRD_FINAL:raise ValueError('third partial audit changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+FOURTH_ID+'.json'),FOURTH_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=FOURTH_ID or audit.get('final_sha256')!=FOURTH_FINAL or audit.get('native_tuple_keys')!=[FOURTH_KEY] or audit.get('raw_pcap_tuple_keys')!=[FOURTH_KEY] or sha(ROOT/'attempts'/HOST/FOURTH_ID/'FINAL.json')!=FOURTH_FINAL:raise ValueError('fourth partial audit changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+FIFTH_ID+'.json'),FIFTH_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=FIFTH_ID or audit.get('final_sha256')!=FIFTH_FINAL or audit.get('native_tuple_keys')!=[FIFTH_KEY] or audit.get('raw_pcap_tuple_keys')!=[FIFTH_KEY] or sha(ROOT/'attempts'/HOST/FIFTH_ID/'FINAL.json')!=FIFTH_FINAL:raise ValueError('fifth partial audit changed')
 audit=json.loads(stable_read(ROOT/('partial-exclusion-'+SIXTH_ID+'.json'),SIXTH_AUDIT))
 if audit.get('capture_credit') is not False or audit.get('attempt_id')!=SIXTH_ID or audit.get('final_sha256')!=SIXTH_FINAL or audit.get('native_tuple_keys')!=[SIXTH_KEY] or audit.get('raw_pcap_tuple_keys')!=[SIXTH_KEY] or sha(ROOT/'attempts'/HOST/SIXTH_ID/'FINAL.json')!=SIXTH_FINAL:raise ValueError('sixth partial audit changed')
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:raise RuntimeError('ownership or history changed')
 if sha(pathlib.Path(__file__))!=CONFIG['owner_sha256']:raise RuntimeError('owner code changed')
 verify_control_diagnostic()
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
 network_policy.inspect_network(MODE,CONFIG['network'],expected_container);network_policy.verify_history_disjoint(history,CONFIG['network']['subnet'])
 if history.get('kind')!='jsdelivr-wtfpad-prior-tuple-history' or history.get('domain')!=HOST or len(history.get('committed',[]))!=400:raise ValueError('prior tuple history invalid')
 entries=history['committed'];slots=[x.get('slot') for x in entries];keys=[k for x in entries for k in x.get('native_tuple_keys',[])]
 reserved=history.get('reserved_native_tuples')
 if sorted(slots)!=list(range(1,401)) or not isinstance(reserved,list) or not reserved or len(set(keys))!=len(keys) or len(set(reserved))!=len(reserved) or set(keys)&set(reserved):raise ValueError('prior tuple exclusions invalid')
 return {'entries':[], 'reserved_native_tuples':sorted(set(keys)|set(reserved))}

def initialize_ledger(history,cutover_sha):
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:raise ValueError('shared ledger module changed')
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['ledger_module']),CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode=MODE,config_sha=OLD_CONFIG_SHA,coverage_sha=CONFIG['coverage_sha256'],history_sha=CONFIG['history_sha256'])
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(PARTIAL_KEY,)).fetchone()!=('cs-buflo',PARTIAL_ID,1,PARTIAL_FINAL,'excluded'):raise ValueError('partial tuple exclusion changed')
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(SECOND_KEY,)).fetchone()!=('cs-buflo',SECOND_ID,1,SECOND_FINAL,'excluded'):raise ValueError('second partial tuple exclusion changed')
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(THIRD_KEY,)).fetchone()!=('cs-buflo',THIRD_ID,1,THIRD_FINAL,'excluded'):raise ValueError('third partial tuple exclusion changed')
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(FOURTH_KEY,)).fetchone()!=('cs-buflo',FOURTH_ID,1,FOURTH_FINAL,'excluded'):raise ValueError('fourth partial tuple exclusion changed')
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(FIFTH_KEY,)).fetchone()!=('cs-buflo',FIFTH_ID,1,FIFTH_FINAL,'excluded'):raise ValueError('fifth partial tuple exclusion changed')
 if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(SIXTH_KEY,)).fetchone()!=('cs-buflo',SIXTH_ID,1,SIXTH_FINAL,'excluded'):raise ValueError('sixth partial tuple exclusion changed')
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
 args=['docker','run','-d','--cap-add','SYS_NICE','--network',CONFIG['network']['id'],'--label','qcsd.owner='+LABEL,
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
 baseline=verify_transfer(container)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 aid=secrets.token_hex(16);directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir();raw=directory/'capture.pcap'
 lock=(directory/'attempt.lock').open('x')
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  network_policy=load_pinned_module(pathlib.Path(CONFIG['network_module']),CONFIG['network_module_sha256']);worker_ip=network_policy.inspect_container(MODE,CONFIG['network'],container)
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
   param_name='params/'+MODE+'.json';native_timeout=480
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json',
    '--chaff-manifest','/inputs/chaff-manifest.json','--config','/inputs/params/custom-receive.toml','--request-policy','half-duplex',
    '--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds',str(native_timeout)]
   with (directory/'invocation.json').open('x') as f:json.dump({'argv':argv,'exec_wrapper':priority_wrapper(argv),'container':container,'seed':seed},f);f.write('\n');f.flush();os.fsync(f.fileno())
   with (directory/'client.log').open('xb') as f:
    exec_begun=True
    code=subprocess.run(['docker','exec',container,*priority_wrapper(argv)],stdout=f,stderr=subprocess.STDOUT,timeout=540).returncode
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
  if not retire and network_policy.inspect_container(MODE,CONFIG['network'],container)!=worker_ip:raise RuntimeError('worker network changed before finalization')
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {}
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  expected_cfg={'schema_version':2,'control_interval_us':10000,'initial_max_stream_data':8192,'automatic_receive_window':1048576,'max_chaff_streams':5,'low_watermark':1000000,'use_empty_resources':False,'max_stream_data_excess':1000,'max_udp_payload_size':1200,'drop_unsatisfied_events':False,'keep_alive_lead_time_us':100000,'tail_wait_us':0,'defense':{'kind':'cs_buflo','parameters':'/inputs/params/cs-buflo.json'}}
  clean=(cfg==expected_cfg and code==0 and not error and cap_ok and defended_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json'],INPUT_SHA['chaff-manifest.json'],MODE,INPUT_SHA['params/'+MODE+'.json']))
  keys=[];collision=[]
  if clean:
   keys=tuple_keys(run)
   try:LEDGER.reserve(db,mode=MODE,slot=slot,attempt=aid,keys=keys,excluded=set(baseline['reserved_native_tuples']))
   except ValueError as e:collision=[{'reason':str(e)}];clean=False;error='duplicate slot or native connection tuple'
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
   'ownership_sha256':CONFIG_SHA,'domain_schedule':'parallel-authorized-20261123','realization_variation_sha256':VARIATION_SHA,'chaff_qualification_sha256':'57714a50604221cc1f01c7c779dd9ffd69e1b74daff2c45c65344ef2c5ba5b67','chaff_variation':'resource 19 to resource 2; 147552-byte qualified response','controller_interval_variation_sha256':CONTROL_VARIATION_SHA,'no_credit_diagnostic_sha256':DIAGNOSTIC_RUN_SHA,'priority_variation_sha256':PRIORITY_NOTE_SHA,'prior_partial_audit_sha256s':[PARTIAL_AUDIT,SECOND_AUDIT,THIRD_AUDIT,FOURTH_AUDIT,FIFTH_AUDIT,SIXTH_AUDIT],'tuple_verifier_sha256':MODULE_SHA,'network_id':CONFIG['network']['id'],'network_subnet':CONFIG['network']['subnet'],'network_worker_ip':worker_ip,'network_manifest_sha256':CONFIG['network_manifest_sha256'],
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'native_tuple_keys':keys,'tuple_collisions':collision,'prior_nonclean_attempts':previous,
   'source_role':'five-defense-recapture-local-20261123','mode_evidence':'native/run.json','files':files}
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  finalsha=store_final(directory,final)
  if clean:
   LEDGER.commit(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha)
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
 if HOST!='cdn.jsdelivr.net' or MODE!='cs-buflo' or ROOT!=domain_root/'modes'/MODE or INPUTS!=domain_root/'diagnostic-cs-control10ms-inputs-001' or NOTE!=domain_root/'inputs/replacement-note.json':raise ValueError('defended mode scope mismatch')
 if CONFIG['exclusive_fence_locks']!=[]:raise ValueError('unexpected fence locks')
 if ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('symlink in replacement scope')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3:raise ValueError('missing minimum guest storage floor')
 ROOT.mkdir(parents=True,exist_ok=True);(ROOT/'attempts'/HOST).mkdir(parents=True,exist_ok=True)
 locks=[]
 for lockpath in [ROOT/'production-owner.lock',*[pathlib.Path(x) for x in CONFIG['exclusive_fence_locks']]]:
  f=lockpath.open('a+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(f)
 baseline=verify_transfer()
 diagnostic_events=ROOT.parent.parent/'diagnostic-cs-control10ms-long-run-001/native/events.csv'
 if sha(diagnostic_events)!=DIAGNOSTIC_EVENTS_SHA:raise ValueError('diagnostic event evidence changed')
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
  while not stopping.is_set() and slot<=400 and failures<10 and capture_failures<20:
   status,screen,retired=attempt(container,stage,db,slot,isolation,CONFIG['history_sha256'])
   if retired:container=None
   if status=='success':slot=advance_success(db,MODE,slot);failures=0;capture_failures=0
   elif not screen:capture_failures+=1
   else:failures+=1
   if args.once or stopping.wait(2):break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  db.close()
 print(json.dumps({'hostname':HOST,'next_slot':slot,'failures':failures,'capture_failures':capture_failures}),flush=True)
if __name__=='__main__':main()
