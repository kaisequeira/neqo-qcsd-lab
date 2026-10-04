"""Execute the launcher's real bounded transport commands with large bodies.

Only pure HOST projection and create-only receipt commands are extracted. These
tests perform no Docker actions and make no claim about measured traffic.
"""
from __future__ import annotations

import base64
import json
import re
import shlex
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SIZES = (128 * 1024 + 8192, 1024 * 1024)
REGIONS = {
    "dispatch": ("parallel_diagnostic=0\n", 'study_cohort_version=""\nstudy_cohort_version_seen=0\n'),
    "workers": (
        "# Two measured workers share one authenticated guardian. All Docker mutations\n",
        "# Every remaining ETF launch is a public campaign.  Give the measured client\n",
    ),
}


def _region(name):
    source = (ROOT / "qcsd-lab").read_text()
    start, end = REGIONS[name]
    assert source.count(start) == source.count(end) == 1
    return source.split(start, 1)[1].split(end, 1)[0]


def _command(region, marker):
    """Keep the actual pipeline, Python body, bounded argv and shell assignment."""
    source = _region(region)
    matches = [match for match in re.finditer(r"/usr/bin/python3 -I -c '(.*?)'", source, re.S)
               if marker in match.group(1)]
    assert len(matches) == 1, marker
    match = matches[0]
    start = source.rfind("\n", 0, match.start()) + 1
    end = source.find("\n", match.end())
    if end == -1:
        end = len(source)
    while source[start:end].rstrip().endswith("\\"):
        following = source.find("\n", end + 1)
        end = len(source) if following == -1 else following
    return source[start:end] + "\n"


def _environment_function():
    source = _region("dispatch")
    start = source.index("parallel_environment_rows() {\n")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def _raw(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _large(size, **fields):
    # Shell metacharacters and escaped NUL are data, even within framed bodies.
    result = {"transport_fixture": "x" * size + '\n$() `literal` "quotes" \\ 雪\u0000', **fields}
    assert len(_raw(result)) > size
    return result


def _run(tmp_path, command, bodies, *, scalars=None, arrays=None, suffix=""):
    output = tmp_path / "output"
    for lane in ("lane-1", "lane-2"):
        (output / lane).mkdir(parents=True, exist_ok=True)
    lines = ["set -euo pipefail", "ROOT=" + shlex.quote(str(ROOT)),
             "parallel_output=" + shlex.quote(str(output))]
    for name, value in (scalars or {}).items():
        lines.append(name + "=" + shlex.quote(str(value)))
    for name, values in (arrays or {}).items():
        lines.append(name + "=(" + " ".join(shlex.quote(str(value)) for value in values) + ")")
    for name, value in bodies.items():
        path = tmp_path / (name + ".body")
        path.write_bytes(value if isinstance(value, bytes) else _raw(value))
        lines.append(name + '="$(cat -- ' + shlex.quote(str(path)) + ')"')
    script = tmp_path / "transport.sh"
    script.write_text("\n".join(lines) + "\n" + command + suffix)
    # Only the small script path crosses execve; every full JSON body uses stdin.
    return subprocess.run(["/bin/bash", str(script)], capture_output=True, timeout=30)


def _assert_created_once(tmp_path, command, bodies, expected, target, **options):
    first = _run(tmp_path, command, bodies, **options)
    assert first.returncode == 0, first.stderr.decode()
    path = tmp_path / "output" / target
    expected_raw = _encoded(expected)
    assert path.read_bytes() == expected_raw
    assert json.loads(path.read_bytes()) == expected
    before = path.stat()
    second = _run(tmp_path, command, bodies, **options)
    assert second.returncode != 0, "the actual receipt writer must remain create-only"
    after = path.stat()
    assert path.read_bytes() == expected_raw
    assert (after.st_ino, after.st_mtime_ns, after.st_size) == (before.st_ino, before.st_mtime_ns, before.st_size)


@pytest.mark.parametrize("size", SIZES)
def test_actual_image_preflight_large_json_is_stdin_and_create_only(tmp_path, size):
    value = _large(size, workers=[{"id": "fixture-worker", "nested": {"verified": True}}])
    command = _command("workers", 'put(Path(sys.argv[2])/"image-preflight.json"')
    _assert_created_once(tmp_path, command, {"QCSD_DOCKER_OUTPUT_PARALLEL_PREFLIGHT": value},
                         value, "image-preflight.json")


@pytest.mark.parametrize("size", SIZES)
def test_actual_launch_multiple_large_json_frames_preserve_inputs(tmp_path, size):
    inspected = [_large(size, Id="worker-a"), _large(size, Id="worker-b")]
    cpu = _large(size, pairs=[[1, 2], [3, 4]], sidecar_cpus=[0])
    available = [0, 1, 2, 3, 4]
    scalars = {"image_id": "sha256:" + "a" * 64, "study_capture_docker_ncpu": 5}
    arrays = {"parallel_worker_ids": ["worker-a", "worker-b"],
              "parallel_router_ids": ["router-a", "router-b"],
              "parallel_network_ids": ["network-a", "network-b"],
              "parallel_worker_names": ["worker-name-a", "worker-name-b"],
              "parallel_router_names": ["router-name-a", "router-name-b"]}
    expected = {
        "workers": [{"id": arrays["parallel_worker_ids"][i], "name": arrays["parallel_worker_names"][i],
                     "image_id": scalars["image_id"], "client_cpu": cpu["pairs"][i][0],
                     "orchestrator_cpu": cpu["pairs"][i][1]} for i in range(2)],
        "sidecars": dict(zip(arrays["parallel_router_names"], arrays["parallel_router_ids"])),
        "lane_resources": [{"worker_id": arrays["parallel_worker_ids"][i],
                            "router_id": arrays["parallel_router_ids"][i],
                            "network_id": arrays["parallel_network_ids"][i]} for i in range(2)],
        "inspected_containers": inspected, "available_cpus": available, "docker_ncpu": 5,
    }
    command = _command("workers", 'put(root/"actual-launch.json"')
    _assert_created_once(tmp_path, command, {"parallel_actual_inspect": inspected,
                         "parallel_cpu_json": cpu, "study_capture_available_cpus_json": available},
                         expected, "actual-launch.json", scalars=scalars, arrays=arrays)


@pytest.mark.parametrize("size", SIZES)
def test_actual_retirement_multiple_large_json_frames_preserve_inputs(tmp_path, size):
    terminal = _large(size, Id="worker-a", State={"Running": False, "ExitCode": 17})
    peer = _large(size, Id="worker-b", State={"Running": True})
    scalars = {"parallel_index": 0, "parallel_exit_code": 17, "parallel_worker_id": "worker-a"}
    arrays = {"parallel_router_ids": ["router-a", "router-b"],
              "parallel_network_ids": ["network-a", "network-b"]}
    expected = {"worker_terminal": terminal, "worker_exit_code": 17,
                "absent_ids": ["network-a", "router-a", "worker-a"], "peer_state": peer}
    command = _command("workers", 'put(root/f"lane-{i+1}"/"actual-retirement.json"')
    _assert_created_once(tmp_path, command, {"parallel_state": [terminal], "parallel_peer_state": [peer]},
                         expected, "lane-1/actual-retirement.json", scalars=scalars, arrays=arrays)


@pytest.mark.parametrize("size", SIZES)
def test_actual_formal_dns_large_frames_keep_exact_raw_body_and_create_only(tmp_path, size):
    dns_path = tmp_path / "pins.json"
    inputs = _large(size, campaign_name="fixture-campaign", dns_path=str(dns_path))
    # Both frames exceed the kernel's per-argument limit independently.
    hosts = [[f"h{i:06d}.example", "8.8.8.8"] for i in range(size // 24 + 100)]
    dns = _raw({"schema_version": 1, "campaign": "fixture-campaign", "hosts": hosts})
    assert len(dns) > size
    bodies = {"parallel_formal_second_inputs": inputs, "QCSD_DOCKER_OUTPUT_PARALLEL_DNS": dns}
    command = _command("workers", 'durable_create(Path(inputs["dns_path"])')
    first = _run(tmp_path, command, bodies)
    assert first.returncode == 0, first.stderr.decode()
    assert dns_path.read_bytes() == dns + b"\n"
    before = dns_path.stat()
    second = _run(tmp_path, command, bodies)
    assert second.returncode != 0
    after = dns_path.stat()
    assert dns_path.read_bytes() == dns + b"\n"
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize("bad", ["campaign", "private-address", "unordered-hosts", "duplicate-key"])
def test_actual_formal_dns_transport_keeps_scientific_rejections(tmp_path, bad):
    dns_path = tmp_path / "pins.json"
    inputs = _large(SIZES[0], campaign_name="fixture-campaign", dns_path=str(dns_path))
    dns = {"schema_version": 1, "campaign": "fixture-campaign", "hosts": [["a.example", "8.8.8.8"]]}
    if bad == "campaign":
        dns["campaign"] = "other-campaign"
    elif bad == "private-address":
        dns["hosts"][0][1] = "127.0.0.1"
    elif bad == "unordered-hosts":
        dns["hosts"] = [["b.example", "8.8.8.8"], ["a.example", "8.8.8.8"]]
    raw = _raw(dns)
    if bad == "duplicate-key":
        raw = raw[:-1] + b',"schema_version":1}'
    result = _run(tmp_path, _command("workers", 'durable_create(Path(inputs["dns_path"])'),
                  {"parallel_formal_second_inputs": inputs, "QCSD_DOCKER_OUTPUT_PARALLEL_DNS": raw})
    assert result.returncode != 0
    assert not dns_path.exists()


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("projection", ["campaign", "dns", "mounts", "cpus", "worker-rows", "state"])
def test_actual_large_body_projections(tmp_path, size, projection):
    dns_path = tmp_path / "worker-dns.json"
    dns_path.write_bytes(_raw({"campaign": "fixture-campaign", "hosts": [["a.example", "8.8.8.8"]]}))
    inputs = _large(size, campaign_name="fixture-campaign", campaign_path="/fixture campaign.yml",
                    dns_path=str(dns_path), result_namespace="fixture-lane", mount_roots=["/one", "/two spaces"])
    region, variable, output_variable, marker = {
        "campaign": ("dispatch", "parallel_formal_first_inputs", "parallel_first_campaign", '["campaign_path"]'),
        "dns": ("dispatch", "parallel_formal_first_inputs", "parallel_formal_dns_path", '["dns_path"]'),
        "mounts": ("workers", "parallel_formal_first_inputs", "parallel_formal_mount_text", '["mount_roots"]'),
        "cpus": ("workers", "parallel_cpu_json", None, 'x["sidecar_cpus"]'),
        "worker-rows": ("workers", "parallel_formal_worker_inputs", "parallel_formal_worker_rows_text",
                        "formal worker DNS belongs to another lane"),
        "state": ("workers", "parallel_state", "parallel_exit_code", 'x["State"]["Running"]'),
    }[projection]
    expected = {"campaign": "/fixture campaign.yml\n", "dns": str(dns_path) + "\n",
                "mounts": "/one\n/two spaces\n", "cpus": "0,5\n1\n2\n1,2\n3\n4\n3,4\n",
                "worker-rows": "fixture-campaign\nfixture-lane\na.example=8.8.8.8\n", "state": "17\n"}[projection]
    value = inputs
    if projection == "cpus":
        value = _large(size, sidecar_cpus=[0, 5], pairs=[[1, 2], [3, 4]])
    elif projection == "state":
        value = [_large(size, State={"Running": False, "ExitCode": 17})]
    suffix = ('printf \'%s\\n\' "${parallel_cpu_rows[@]}"\n' if output_variable is None else
              'printf \'%s\\n\' "${' + output_variable + '}"\n')
    result = _run(tmp_path, _command(region, marker), {variable: value}, suffix=suffix)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.decode() == expected


@pytest.mark.parametrize("size", SIZES)
def test_actual_environment_rows_large_body_and_decode(tmp_path, size):
    environment = {"QCSD_RAPID_ROLLING_LAUNCH_INPUT": '/fixture "quoted" $() `data` 雪.json',
                   "QCSD_RAPID_COLLECTION_COMPATIBILITY": "/fixture-compatible.json"}
    inputs = _large(size, environment=environment)
    command = _environment_function() + '\nparallel_environment_rows "${fixture_body}"\n'
    result = _run(tmp_path, command, {"fixture_body": inputs})
    assert result.returncode == 0, result.stderr.decode()
    rows = [line.split("\t", 1) for line in result.stdout.decode().splitlines()]
    assert [row[0] for row in rows] == sorted(environment)
    decoder = _command("dispatch", "base64.b64decode(sys.stdin.buffer.read(),validate=True)")
    for key, encoded in rows:
        result = _run(tmp_path, decoder, {"parallel_environment_b64": encoded.encode()},
                      suffix='printf \'%s\' "${parallel_environment_value}"\n')
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.decode() == environment[key]
        assert base64.b64decode(encoded).decode() == environment[key]


@pytest.mark.parametrize("environment", [{"UNDECLARED": "input"}, {"QCSD_RAPID_ROLLING_LAUNCH_INPUT": "bad\u0000value"}])
def test_actual_environment_transport_keeps_control_input_rejections(tmp_path, environment):
    result = _run(tmp_path, _environment_function() + '\nparallel_environment_rows "${fixture_body}"\n',
                  {"fixture_body": _large(SIZES[0], environment=environment)})
    assert result.returncode != 0


def test_actual_worker_rows_still_reject_another_lanes_dns(tmp_path):
    dns_path = tmp_path / "wrong-lane-dns.json"
    dns_path.write_bytes(_raw({"campaign": "other-campaign", "hosts": [["a.example", "8.8.8.8"]]}))
    result = _run(tmp_path, _command("workers", "formal worker DNS belongs to another lane"),
                  {"parallel_formal_worker_inputs": _large(SIZES[0], campaign_name="fixture-campaign",
                                                           result_namespace="fixture-lane", dns_path=str(dns_path))})
    assert result.returncode != 0
