"""Exercise the actual batch shell with only Docker/lifecycle actuation replaced."""
import json
import shlex
import subprocess
from pathlib import Path

import pytest

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
    if state.get('workers') and key==state['workers'][0]:
        time.sleep(.05 if state.get('fast_first_removal') else 3.25)
    state['events'].append('remove-'+key);containers.pop(key,None)
elif args[:2]==['network','rm']: networks.pop(args[-1],None)
elif args[0]=='retire':
    kind,key,registration=args[1:]
    retired=state.setdefault('retirements',[])
    if any(row['id']==key for row in retired):
        raise SystemExit('resource handoff was already retired: '+key)
    retired.append(dict(kind=kind,id=key,registration=registration))
elif args[0]=='presence': print('present' if args[1] in containers else 'absent')
elif args[0]=='network-presence': print('present' if args[1] in networks else 'absent')
else: raise SystemExit('unexpected fake Docker operation '+repr(args))
save()
'''


def _environment_helper(source):
    # Execute the launcher's real decoder in the extracted shell fixture too.
    return "parallel_environment_rows() {" + source.split("parallel_environment_rows() {", 1)[1].split(
        '\nif [[ "${1:-}" == "parallel-diagnostic-run" ||', 1)[0]


@pytest.mark.parametrize("formal", [False, True])
def test_parallel_command_uses_official_formal_dns_sink_only_when_opted_in(context, formal):
    project = Path(__file__).resolve().parents[1]
    source = (project / "qcsd-lab").read_text()
    setup = source.split('if [[ "${1:-}" == "parallel-diagnostic-run" ||', 1)[1]
    setup = 'if [[ "${1:-}" == "parallel-diagnostic-run" ||' + setup.split('\nstudy_cohort_version=""', 1)[0]
    execution = Path(context.authority["runtime"]["execution_root"])
    output = execution / "results" / "batch-operator"
    output.mkdir(parents=True)
    official_dns = execution / "evidence" / "lanes" / "buflo" / "dns.json"
    campaign = context.authority["campaigns"][0]["path"]
    inputs = json.dumps(dict(dns_path=str(official_dns), campaign_path=campaign))
    prefix = "\n".join([
        "set -euo pipefail", "ROOT=" + shlex.quote(str(execution)),
        "parallel_diagnostic=0", "parallel_formal=0",
        "QCSD_PARALLEL_AUTHORITY_SHA256=" + shlex.quote(context.digest),
        _environment_helper(source),
        'parallel_select_host_python() { printf "%s\\n" "/usr/bin/python3"; }',
        'require_docker() { return 0; }',
        "parallel_python() { if [[ \"$1\" == select ]]; then printf '%s\\n' " + shlex.quote(campaign) +
        "; elif [[ \"$1\" == lifecycle-inputs ]]; then return 0; elif [[ \"$1\" == formal-entry-inputs ]]; then printf '%s\\n' " + shlex.quote(inputs) + "; else return 99; fi; }",
    ])
    result = subprocess.run([
        "bash", "-c", prefix + "\n" + setup +
        '\nprintf "%s\\n" "$parallel_diagnostic" "$parallel_formal" "$QCSD_RAPID_DNS_RECEIPT_PATH" "$1" "$2"',
        "parallel-command-test", "parallel-formal-run" if formal else "parallel-diagnostic-run",
        str(context.path), str(output),
    ], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "1", str(int(formal)), str(official_dns if formal else output / "dns-pins.json"), "run", campaign,
    ]
    assert not official_dns.exists()


@pytest.mark.parametrize("role,version,contract", [
    ("diagnostic", "v5", parallel.NATIVE_CONTRACT),
    ("formal", "v4", parallel.NATIVE_CONTRACT),
    ("formal", "v5", "qcsd-client-rr1-etf-helper-v3"),
])
def test_formal_shell_guard_rejects_wrong_lane_or_native_contract(role, version, contract):
    project = Path(__file__).resolve().parents[1]
    source = (project / "qcsd-lab").read_text()
    guard = source.split("# Two measured workers share one authenticated guardian.", 1)[1]
    guard = guard.split("\n", 1)[1].split('  parallel_lock="', 1)[0] + "fi\n"
    prefix = "\n".join([
        "set -euo pipefail", "parallel_diagnostic=1", "parallel_formal=1", "rapid_capture=1",
        "rapid_capture_role=" + shlex.quote(role), "rapid_capture_version=" + shlex.quote(version),
        "study_capture_scheduler_contract=" + shlex.quote(contract),
    ])
    result = subprocess.run(["bash", "-c", prefix + "\n" + guard], text=True, capture_output=True, timeout=10)
    assert result.returncode == 2
    assert "official rapid v5 or prospective rolling v6 formal lanes" in result.stderr


@pytest.mark.parametrize("formal,release_failure", [(False, False), (True, False), (True, True)])
def test_real_shell_retires_failed_lane_while_peer_continues(context, tmp_path, formal, release_failure):
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
    state.write_text(json.dumps(dict(containers={}, networks={}, workers=[], next=0, events=[],
                                     fast_first_removal=release_failure)))
    preflight = (context.output / "image-preflight.json").read_text()
    (context.output / "image-preflight.json").unlink()
    quoting = shlex.quote
    dns_second = json.dumps({"schema_version": 1, "campaign": "cs-buflo",
                             "hosts": [["second.example", "1.0.0.1"]]})
    inputs = []
    evidence = context.output / "formal-evidence"
    for index, row in enumerate(context.authority["campaigns"]):
        name = Path(row["path"]).stem
        dns = evidence / "lanes" / name / "dns.json"
        if formal:
            dns.parent.mkdir(parents=True)
        inputs.append(dict(campaign_path=row["path"], campaign_name=name,
                           result_namespace=str(Path(context.authority["runtime"]["execution_root"]) / "results" / name),
                           dns_path=str(dns), mount_roots=[str(evidence), str(context.runtime)]))
    if formal:
        Path(inputs[0]["dns_path"]).write_text(json.dumps({
            "schema_version": 1, "campaign": "buflo", "hosts": [["first.example", "1.1.1.1"]],
        }) + "\n")
    formal_inputs = tmp_path / "formal-inputs.json"
    formal_inputs.write_text(json.dumps(inputs))
    formal_helper = tmp_path / "formal_actuator_inputs.py"
    formal_helper.write_text('''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]+"/src")
from qcsd_lab import rapid_parallel_capture as parallel
rows=json.loads(Path(sys.argv[2]).read_text()); args=sys.argv[3:]
book=(Path(args[args.index("--output")+1])/"test-only-prepared-book.json"
      if "--output" in args else None)
if args[0]=="prepare-release":
    print(parallel.put(book,dict(schema_version=1,artifact_type="test-only-shell-preparation",
                                 scientific_credit=False)))
elif args[0] in {"formal-inputs","release"}:
    if (book is None or not book.is_file() or "--prepared-sha256" not in args
        or args[args.index("--prepared-sha256")+1]!=parallel.sha(parallel.read(book))):
        raise SystemExit("test-only prepared SHA did not reach worker and release")
    if args[0]=="release":
        index=args.index("--prepared-sha256")
        del args[index:index+2]
        parallel.main(args)
    else:
        print(json.dumps(rows[int(args[args.index("--index")+1])]))
else:
    parallel.main(args)
    if args[0]=="initialize":
        for row in rows: Path(row["result_namespace"]).mkdir(parents=True)
''')
    capture_calls = tmp_path / "capture-preflight-calls.log"
    network_calls = tmp_path / "network-create-calls.log"
    completed_peer = Path(context.authority["runtime"]["execution_root"]) / "results" / "prior-completed-peer" / "complete.json"
    completed_peer.parent.mkdir(parents=True)
    completed_peer.write_bytes(b"preserved independently verified peer\n")
    peer_before = (completed_peer.read_bytes(), completed_peer.stat().st_mtime_ns, completed_peer.stat().st_ino)
    prefix = "\n".join([
        "set -euo pipefail", "ROOT=" + quoting(str(project)),
        'source "${ROOT}/tools/docker_signal_supervisor.sh"',
        "parallel_diagnostic=1", "parallel_formal=" + str(int(formal)), "rapid_capture=1",
        "QCSD_TEST_FAIL_RELEASE=" + str(int(release_failure)),
        "rapid_capture_role=" + ("formal" if formal else "diagnostic"),
        "rapid_capture_version=" + ("v6" if formal else ""),
        "parallel_formal_first_inputs=" + quoting(json.dumps({**inputs[0], "second_worker_inputs": inputs[1]})),
        "study_capture_scheduler_contract=" + quoting(parallel.NATIVE_CONTRACT),
        "parallel_authority=" + quoting(str(context.path)), "parallel_output=" + quoting(str(context.output)),
        "parallel_authority_sha256=" + quoting(context.digest), "image_id=" + quoting(context.actual["workers"][0]["image_id"]),
        "study_capture_available_cpus_json='[0,2,4,7,9]'", "study_capture_docker_ncpu=16",
        "qcsd_invoking_uid=$(id -u)", "qcsd_invoking_gid=$(id -g)",
        "container=(docker run --network bridge --cpuset-cpus 7,9 --env QCSD_CAPTURE_CLIENT_CPU=7 --env QCSD_CAPTURE_ORCHESTRATOR_CPU=9 --env QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64= --add-host inherited.example=8.8.8.8)",
        "fake() { /usr/bin/python3 " + quoting(str(fake)) + " " + quoting(str(state)) + " " + quoting(str(context.output)) + ' "$@"; }',
        "parallel_python() { if [[ \"$1\" == release && \"$QCSD_TEST_FAIL_RELEASE\" == 1 ]]; then return 37; fi; /usr/bin/python3 -I -c 'import sys;sys.path.insert(0,sys.argv.pop(1)+\"/src\");from qcsd_lab.rapid_parallel_capture import main;main()' \"$ROOT\" \"$@\"; }",
        "qcsd_capture_attached_docker_output() { local -n result=$1; shift; printf '%s\\n' \"$*\" >>" + quoting(str(capture_calls)) +
        "; if [[ \" $* \" == *' formal-dns '* ]]; then result=" + quoting(dns_second) + "; else result=" + quoting(preflight) + "; fi; }",
        '_qcsd_docker_api() { fake "$@"; }',
        '_QCSD_LIFETIME_SIGNAL_STATUS=0',
        '_qcsd_docker_api_with_timeout() { local duration=$1; printf "%s %s\\n" "$1" "${*:2}" >>' + quoting(str(tmp_path / "removal-durations.log")) + '; shift; timeout "$duration" /usr/bin/python3 ' + quoting(str(fake)) + ' ' + quoting(str(state)) + ' ' + quoting(str(context.output)) + ' "$@"; }',
        '_qcsd_docker_exact_id_presence() { fake presence "$1"; }',
        '_qcsd_docker_exact_network_presence() { fake network-presence "$1"; }',
        'qcsd_create_docker_network() { local -n result=$1; local name=${!#}; printf "%s\\n" "$*" >>' + quoting(str(network_calls)) + '; result+=("$(fake create-network "$name")"); }',
        'start_kernel_tx_public_router() { kernel_tx_public_router_id=$(fake create-router "$1" "$study_capture_sidecar_cpuset" "$image_id"); QCSD_DOCKER_IDS_PUBLIC_ROUTERS+=("$kernel_tx_public_router_id"); }',
        'prepare_kernel_tx_capture_root() { :; }',
        'kernel_tx_public_network_receipt_base64() { echo test-only-topology; }',
        'kernel_tx_public_observer_binding_base64() { echo test-only-observer; }',
        'qcsd_run_detached_docker() { local -n result=$1; shift; result+=("$(fake create-worker "$@" --image-id "$image_id")"); }',
        'qcsd_retire_docker_handoff() { fake retire "$@"; }',
        '_qcsd_begin_latched_cleanup() { :; }', '_qcsd_finish_latched_cleanup() { exit "$cleanup_entry_status"; }',
        _environment_helper(source),
        'parallel_select_host_python() { printf "%s\\n" "/usr/bin/python3"; }',
        source.split('replace_container_option_value() {', 1)[1].split('_qcsd_latch_cleanup_signal()', 1)[0].join(['replace_container_option_value() {', '']),
    ])
    if formal:
        prefix += "\nparallel_python() { if [[ \"$1\" == release && \"$QCSD_TEST_FAIL_RELEASE\" == 1 ]]; then return 37; fi; /usr/bin/python3 " + quoting(str(formal_helper)) + ' "$ROOT" ' + quoting(str(formal_inputs)) + ' "$@"; }'
    result = subprocess.run(["bash", "-c", prefix + "\n" + block], text=True, capture_output=True, timeout=30)
    prepared_book = context.output / "test-only-prepared-book.json"
    if formal:
        assert parallel.load(prepared_book) == {
            "schema_version": 1, "artifact_type": "test-only-shell-preparation", "scientific_credit": False,
        }
        prepared_digest = parallel.sha(parallel.read(prepared_book))
    else:
        assert not prepared_book.exists()
    if release_failure:
        assert result.returncode == 37, result.stderr
        assert (context.output / "actual-launch.json").exists()
        assert not (context.output / "batch-launch.json").exists()
        assert not list(context.output.glob("lane-*/gate/release.json"))
        observed = json.loads(state.read_text())
        assert len(observed["workers"]) == 2
        assert observed["containers"] == {} and observed["networks"] == {}
        assert len(observed["retirements"]) == 6
        assert len((tmp_path / "removal-durations.log").read_text().splitlines()) == 6
        assert (completed_peer.read_bytes(), completed_peer.stat().st_mtime_ns, completed_peer.stat().st_ino) == peer_before
        return
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
    assert len(observed["retirements"]) == 6
    assert len({row["id"] for row in observed["retirements"]}) == 6
    created_networks = [shlex.split(row) for row in network_calls.read_text().splitlines()]
    assert len(created_networks) == 2
    assert all("--internal" not in row for row in created_networks)
    assert all(row[1:6] == ["docker", "network", "create", "--driver", "bridge"] for row in created_networks)
    assert observed["events"].index("remove-" + observed["workers"][0]) < observed["events"].index("terminal-1")
    removal_calls = (tmp_path / "removal-durations.log").read_text().splitlines()
    assert len(removal_calls) == 6
    assert all(row.startswith("30 ") for row in removal_calls)
    assert (completed_peer.read_bytes(), completed_peer.stat().st_mtime_ns, completed_peer.stat().st_ino) == peer_before
    preflight_calls = capture_calls.read_text().splitlines()
    assert len(preflight_calls) == (2 if formal else 1)
    if formal:
        assert "--network bridge" in preflight_calls[1]
        assert "-I -m qcsd_lab.rapid_parallel_capture formal-dns --authority /parallel-authority.json --index 1" in preflight_calls[1]
        assert json.loads(Path(inputs[1]["dns_path"]).read_text()) == json.loads(dns_second)
    for index in range(2):
        gate = parallel.load(context.output / f"lane-{index+1}/gate/host-partition.json")
        assert gate["schema_version"] == 5
        argv = parallel.load(context.output / f"lane-{index+1}/worker-argv.json")
        if formal:
            assert "org.qcsd.release-preparation-sha256=" + prepared_digest in argv
            assert inputs[index]["result_namespace"] + ":/lab/results/" + inputs[index]["campaign_name"] + ":rw" in argv
            assert str(project / "results") + ":/lab/results:ro" in argv
            assert not any(value.endswith(":/lab/results:rw") for value in argv)
            assert [argv[i+1] for i, value in enumerate(argv[:-1]) if value == "--add-host"] == [
                "first.example=1.1.1.1" if index == 0 else "second.example=1.0.0.1",
            ]
            assert str(evidence) + ":" + str(evidence) + ":ro" in argv
            assert argv.count(str(context.runtime) + ":" + str(context.runtime) + ":ro") == 1
        else:
            assert str(context.output / f"lane-{index+1}/results") + ":/lab/results:rw" in argv
            assert "inherited.example=8.8.8.8" in argv
        assert argv[argv.index("--cpuset-cpus")+1] == ("2,4" if index == 0 else "7,9")
