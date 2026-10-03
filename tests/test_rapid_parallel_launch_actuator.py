"""Exercise the actual batch shell with only Docker/lifecycle actuation replaced."""
import json
import shlex
import subprocess
from pathlib import Path

from tests.test_rapid_parallel_capture import context
from qcsd_lab import rapid_parallel_capture as parallel


FAKE_DOCKER = r'''
import json,sys,time
from pathlib import Path
path=Path(sys.argv[1]); output=Path(sys.argv[2]); args=sys.argv[3:]
state=json.loads(path.read_text()); containers=state['containers']; networks=state['networks']
def save(): path.write_text(json.dumps(state))
def oid():
    state['next']+=1
    return format(state['next'],'064x')
def option(name):
    return [args[i+1] for i,x in enumerate(args[:-1]) if x==name][-1]
def container(name,cpus,image,role):
    key=oid()
    containers[key]=dict(Id=key,Name='/'+name,Image=image,HostConfig=dict(CpusetCpus=cpus),
        Config=dict(Labels={'org.qcsd.owner':'qcsd-lab','org.qcsd.study':'parallel-diagnostic','org.qcsd.role':role}),
        State=dict(Status='running',Running=True,ExitCode=0))
    return key
if args[0]=='create-network':
    key=oid();networks[key]=args[1];print(key)
elif args[0]=='create-router': print(container(*args[1:4],'network-router'))
elif args[0]=='create-worker':
    key=container(option('--name'),option('--cpuset-cpus'),option('--image-id'),'parallel-diagnostic-worker')
    state['workers'].append(key);print(key)
elif args[:2]==['container','ls']: print('\n'.join(k for k,v in containers.items() if v['State']['Running']))
elif args[:2]==['network','inspect']: print('10.42.0.0/24')
elif args[:2]==['container','inspect']:
    if '--format' in args: print('10.42.0.2')
    else:
        keys=args[2:]
        if len(keys)==1 and keys[0] in state['workers'] and (output/'batch-launch.json').exists():
            key=keys[0];index=state['workers'].index(key)
            if index==0 or state['workers'][0] not in containers:
                containers[key]['State'].update(Status='exited',Running=False,ExitCode=1 if index==0 else 0)
                state['events'].append('terminal-'+str(index))
        print(json.dumps([containers[k] for k in keys]))
elif args[0]=='logs': print('test-only retained worker output')
elif args[0]=='rm':
    key=args[-1]
    if state.get('workers') and key==state['workers'][0]: time.sleep(3.25)
    state['events'].append('remove-'+key);containers.pop(key,None)
elif args[:2]==['network','rm']: networks.pop(args[-1],None)
elif args[0]=='presence': print('present' if args[1] in containers else 'absent')
elif args[0]=='network-presence': print('present' if args[1] in networks else 'absent')
else: raise SystemExit('unexpected fake Docker operation '+repr(args))
save()
'''


def test_real_shell_retires_failed_lane_while_peer_continues(context, tmp_path):
    project = Path(__file__).resolve().parents[1]
    source = (project / "qcsd-lab").read_text()
    block = source.split("# Two measured workers share one authenticated guardian.", 1)[1]
    block = block.split("\n", 1)[1]
    block = block.split("# Every remaining ETF launch is a public campaign.", 1)[0]
    lock = tmp_path / "private-adapter.lock"
    block = block.replace('parallel_lock="/var/tmp/qcsd-rapid-capture-$(id -u).lock"',
                          "parallel_lock=" + shlex.quote(str(lock)))
    fake = tmp_path / "fake_docker.py"
    fake.write_text(FAKE_DOCKER)
    state = tmp_path / "docker-state.json"
    state.write_text(json.dumps(dict(containers={}, networks={}, workers=[], next=0, events=[])))
    preflight = (context.output / "image-preflight.json").read_text()
    (context.output / "image-preflight.json").unlink()
    quoting = shlex.quote
    prefix = "\n".join([
        "set -euo pipefail", "ROOT=" + quoting(str(project)),
        'source "${ROOT}/tools/docker_signal_supervisor.sh"',
        "parallel_diagnostic=1", "rapid_capture=1", "rapid_capture_role=diagnostic", "rapid_capture_version=",
        "study_capture_scheduler_contract=" + quoting(parallel.NATIVE_CONTRACT),
        "parallel_authority=" + quoting(str(context.path)), "parallel_output=" + quoting(str(context.output)),
        "parallel_authority_sha256=" + quoting(context.digest), "image_id=" + quoting(context.actual["workers"][0]["image_id"]),
        "study_capture_available_cpus_json='[0,2,4,7,9]'", "study_capture_docker_ncpu=16",
        "qcsd_invoking_uid=$(id -u)", "qcsd_invoking_gid=$(id -g)",
        "container=(docker run --network bridge --cpuset-cpus 7,9 --env QCSD_CAPTURE_CLIENT_CPU=7 --env QCSD_CAPTURE_ORCHESTRATOR_CPU=9 --env QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64=)",
        "fake() { /usr/bin/python3 " + quoting(str(fake)) + " " + quoting(str(state)) + " " + quoting(str(context.output)) + ' "$@"; }',
        "parallel_python() { /usr/bin/python3 -I -c 'import sys;sys.path.insert(0,sys.argv.pop(1)+\"/src\");from qcsd_lab.rapid_parallel_capture import main;main()' \"$ROOT\" \"$@\"; }",
        "qcsd_capture_attached_docker_output() { local -n result=$1; result=" + quoting(preflight) + "; }",
        '_qcsd_docker_api() { fake "$@"; }',
        '_QCSD_LIFETIME_SIGNAL_STATUS=0',
        '_qcsd_docker_api_with_timeout() { local duration=$1; printf "%s %s\\n" "$1" "${*:2}" >>' + quoting(str(tmp_path / "removal-durations.log")) + '; shift; timeout "$duration" /usr/bin/python3 ' + quoting(str(fake)) + ' ' + quoting(str(state)) + ' ' + quoting(str(context.output)) + ' "$@"; }',
        '_qcsd_docker_exact_id_presence() { fake presence "$1"; }',
        '_qcsd_docker_exact_network_presence() { fake network-presence "$1"; }',
        'qcsd_create_docker_network() { local -n result=$1; local name=${!#}; result+=("$(fake create-network "$name")"); }',
        'start_kernel_tx_public_router() { kernel_tx_public_router_id=$(fake create-router "$1" "$study_capture_sidecar_cpuset" "$image_id"); QCSD_DOCKER_IDS_PUBLIC_ROUTERS+=("$kernel_tx_public_router_id"); }',
        'prepare_kernel_tx_capture_root() { :; }',
        'kernel_tx_public_network_receipt_base64() { echo test-only-topology; }',
        'kernel_tx_public_observer_binding_base64() { echo test-only-observer; }',
        'qcsd_run_detached_docker() { local -n result=$1; shift; result+=("$(fake create-worker "$@" --image-id "$image_id")"); }',
        'qcsd_retire_docker_handoff() { local -n values=$3; local value; local -a keep=(); for value in "${values[@]}"; do [[ "$value" == "$2" ]] || keep+=("$value"); done; values=("${keep[@]}"); }',
        '_qcsd_begin_latched_cleanup() { :; }', '_qcsd_finish_latched_cleanup() { exit "$cleanup_entry_status"; }',
        source.split('replace_container_option_value() {', 1)[1].split('_qcsd_latch_cleanup_signal()', 1)[0].join(['replace_container_option_value() {', '']),
    ])
    result = subprocess.run(["bash", "-c", prefix + "\n" + block], text=True, capture_output=True, timeout=30)
    assert result.returncode == 1, result.stderr
    assert (context.output / "lane-1/retirement.json").exists(), result.stderr
    first = parallel.load(context.output / "lane-1/retirement.json")
    second = parallel.load(context.output / "lane-2/retirement.json")
    assert first["actual"]["worker_exit_code"] == 1
    assert first["actual"]["peer_state"]["State"]["Running"] is True
    assert second["actual"]["worker_exit_code"] == 0
    assert second["actual"]["peer_retirement_sha256"] == parallel.sha(parallel.read(context.output / "lane-1/retirement.json"))
    observed = json.loads(state.read_text())
    assert observed["containers"] == {} and observed["networks"] == {}
    assert observed["events"].index("remove-" + observed["workers"][0]) < observed["events"].index("terminal-1")
    removal_calls = (tmp_path / "removal-durations.log").read_text().splitlines()
    assert len(removal_calls) == 6
    assert all(row.startswith("30 ") for row in removal_calls)
    for index in range(2):
        gate = parallel.load(context.output / f"lane-{index+1}/gate/host-partition.json")
        assert gate["schema_version"] == 5
        argv = parallel.load(context.output / f"lane-{index+1}/worker-argv.json")
        assert str(context.output / f"lane-{index+1}/results") + ":/lab/results:rw" in argv
        assert argv[argv.index("--cpuset-cpus")+1] == ("2,4" if index == 0 else "7,9")
