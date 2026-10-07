"""Both preflight transports must come from one closed scientific host read."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as parallel


ROOT = Path(__file__).resolve().parents[1]


def test_both_disjoint_worker_transports_share_one_audit_and_final_fence(tmp_path, monkeypatch):
    dependency = tmp_path / "authority.json"
    dependency.write_bytes(b"unchanged authority")
    audited = ({"authority": "same exact source"}, ["lane-zero", "lane-one"])
    audit_contexts = []
    worker_calls = []

    def audit(path, *, _context=None):
        assert path == dependency
        audit_contexts.append(_context)
        _context.watch_file(dependency)
        return audited

    def worker_inputs(path, index, *, _audited=None, _context=None):
        assert path == dependency and _audited is audited and _context is audit_contexts[0]
        worker_calls.append(index)
        return {"campaign_name": f"lane-{index}", "campaign_path": f"/campaign-{index}.yml",
                "dns_path": f"/lane-{index}/dns.json", "mount_roots": [f"/lane-{index}"],
                "environment": {}}

    def host_source(value):
        assert value is audited[0]

    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(formal, "worker_inputs", worker_inputs)
    monkeypatch.setattr(parallel, "host_source", host_source)
    result = parallel.formal_entry_inputs(dependency)
    assert len(audit_contexts) == 1 and worker_calls == [0, 1]
    assert result["campaign_name"] == "lane-0"
    assert result["second_worker_inputs"]["campaign_name"] == "lane-1"
    assert result["dns_path"] != result["second_worker_inputs"]["dns_path"]
    assert result["mount_roots"] != result["second_worker_inputs"]["mount_roots"]


@pytest.mark.parametrize("change", ["bytes", "mode"])
def test_second_transport_cannot_escape_final_dependency_fence(tmp_path, monkeypatch, change):
    dependency = tmp_path / "authority.json"
    dependency.write_bytes(b"unchanged authority")
    dependency.chmod(0o600)
    audited = ({"authority": "same exact source"}, ["lane-zero", "lane-one"])

    def audit(path, *, _context=None):
        _context.watch_file(dependency)
        return audited

    def worker_inputs(path, index, *, _audited=None, _context=None):
        assert _audited is audited and index in (0, 1)
        if index == 1:
            if change == "bytes":
                dependency.write_bytes(b"changed authority")
            else:
                dependency.chmod(0o644)
        return {"campaign_name": f"lane-{index}"}

    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(formal, "worker_inputs", worker_inputs)
    monkeypatch.setattr(parallel, "host_source", lambda value: None)
    with pytest.raises(ValueError, match="operation dependency bytes or mode changed"):
        parallel.formal_entry_inputs(dependency)


def test_launcher_extracts_second_worker_from_first_closed_transport():
    lines = (ROOT / "qcsd-lab").read_text().splitlines()
    matches = [line for line in lines if line.lstrip().startswith("parallel_formal_second_inputs=")]
    assert len(matches) == 1
    assert "parallel_python formal-inputs" not in matches[0]
    first = {"campaign_name": "lane-zero", "dns_path": "/first/dns.json",
             "second_worker_inputs": {"campaign_name": "lane-one", "dns_path": "/second/dns.json"}}
    script = ("set -euo pipefail\nparallel_formal_first_inputs="
              + shlex.quote(json.dumps(first)) + "\n" + matches[0] + "\n"
              + "builtin printf '%s' \"${parallel_formal_second_inputs}\"\n")
    result = subprocess.run(["/bin/bash", "-c", script], text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == first["second_worker_inputs"]
