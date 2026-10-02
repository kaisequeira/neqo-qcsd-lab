"""Exercise publication/recovery boundaries after independent site validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_site_admission as admission


@pytest.fixture
def cli():
    path = Path(__file__).parents[1] / "tools/rapid_plan.py"
    spec = importlib.util.spec_from_file_location("rapid_plan_cli_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _setup(tmp_path, monkeypatch, *, final=False):
    root = tmp_path / "acquisition"
    root.mkdir()
    profile_raw = json.dumps({"schema_version": 5, "receipt_type": plan.V5_PROFILE_RECEIPT_TYPE}).encode()
    profile = root / "profile.json"
    profile.write_bytes(profile_raw)
    monkeypatch.setattr(plan, "FROZEN_V5_PROFILE_SHA256", _sha(profile_raw))
    cohort = root / "cohort.json"
    generation = "final-50" if final else "launch-10"
    cohort.write_bytes(json.dumps({"schema_version": 5, "receipt_type": plan.V5_COHORT_RECEIPT_TYPE,
                                  "payload": {"generation": generation,
                                              "profile_receipt_sha256": _sha(profile_raw)}}).encode())
    provenance = admission._bind(admission.PROVENANCE_TYPE, {"inputs": {
        "profile": {"path": profile.name, "sha256": _sha(profile_raw)},
    }})
    (root / "provenance.json").write_bytes(admission._json(provenance))
    context = SimpleNamespace(root=root, profile_bytes=profile_raw,
                              provenance_sha256=_sha(admission._json(provenance)))
    monkeypatch.setattr(admission, "load_admission_context", lambda path: context)
    workload_root = tmp_path / "workloads"
    workload_root.mkdir()
    count = 50 if final else 10
    sites = []
    for index in range(count):
        raw = json.dumps({"workload": index}).encode()
        name = f"site-{index}"
        (workload_root / f"{name}.json").write_bytes(raw)
        sites.append(plan.Site(f"candidate-{index}", name, _sha(raw), f"https://site{index}.example",
                               f"shard-{index // 5}", f"{index // 5 + 1:064x}"))
    spec = tmp_path / "qualification-spec.json"
    spec.write_text(json.dumps({"schema_version": 1, "qualification_sets": [{
        "qualification_set": f"shard-{index}", "manifest": f"q{index}/manifest.json",
        "sidecar_root": f"q{index}", "prefix_spec_root": None,
    } for index in range(count // 5)]}))
    calls = []

    def qualified(context_arg, cohort_arg, **kwargs):
        calls.append((context_arg, cohort_arg, kwargs))
        return tuple(sites)

    monkeypatch.setattr(admission, "qualified_capture_sites", qualified)
    campaigns = tmp_path / "campaigns"
    campaigns.mkdir()
    # File durability belongs to util; this test exercises immutable inventory.
    monkeypatch.setattr(plan, "durable_create", lambda path, raw: path.write_bytes(raw))
    args = SimpleNamespace(command="publish", root=root, cohort=cohort,
                           qualification_spec=spec, workload_root=workload_root,
                           campaign_dir=campaigns, output=tmp_path / "plan.json")
    return args, calls


@pytest.mark.parametrize("final,lanes,traces", [(False, 10, 50), (True, 800, 16_000)])
def test_publish_and_reopen_fixed_grid(cli, tmp_path, monkeypatch, final, lanes, traces):
    args, calls = _setup(tmp_path, monkeypatch, final=final)
    published = cli.run(args)
    assert published["lane_count"] == lanes
    assert published["planned_trace_count"] == traces
    assert published["formal_accepted_trace_count"] == 0
    assert published["scientific_credit"] is False
    assert calls[-1][2]["qualification_sets"][0]["manifest"] == tmp_path / "q0/manifest.json"
    args.command = "verify"
    verified = cli.run(args)
    assert verified["valid"] is True
    assert verified["planned_trace_count"] == traces
    assert len(calls) == 2  # Both paths independently reopen site/qualification evidence.


def test_changed_campaign_or_spec_is_rejected(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)
    cli.run(args)
    args.command = "verify"
    campaign = next(args.campaign_dir.glob("*.yml"))
    raw = campaign.read_bytes()
    campaign.write_bytes(raw + b"# modified\n")
    with pytest.raises(ValueError, match="campaign bytes"):
        cli.run(args)
    campaign.write_bytes(raw)
    args.qualification_spec.write_bytes(args.qualification_spec.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="reopened acquisition"):
        cli.run(args)


def test_admission_failure_prevents_any_publication(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)

    def fail(*_, **__):
        raise ValueError("qualifier changed")

    monkeypatch.setattr(admission, "qualified_capture_sites", fail)
    with pytest.raises(ValueError, match="qualifier changed"):
        cli.run(args)
    assert not args.output.exists()
    assert list(args.campaign_dir.iterdir()) == []


def test_resealed_boolean_counter_is_not_an_integer(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)
    cli.run(args)
    payload = admission._unpack(args.output.read_bytes(), cli.PLAN_TYPE)
    payload["formal_accepted_trace_count"] = False  # Python equality alone treats this as 0.
    args.output.write_bytes(admission._json(admission._bind(cli.PLAN_TYPE, payload)))
    args.command = "verify"
    with pytest.raises(ValueError, match="reopened acquisition"):
        cli.run(args)


def test_existing_output_preserves_campaigns(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)
    args.output.write_bytes(b"preserve\n")
    with pytest.raises(FileExistsError, match="create-only"):
        cli.run(args)
    assert args.output.read_bytes() == b"preserve\n"
    assert list(args.campaign_dir.iterdir()) == []


def test_successor_publishes_only_one_lane_and_reopens_predecessor(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)
    cli.run(args)
    manifest = admission._unpack(args.output.read_bytes(), cli.PLAN_TYPE)
    args.command = "successor"
    args.lane = manifest["lanes"][3]["campaign_name"]
    args.generation = 2
    args.output = tmp_path / "successor.json"
    published = cli.run(args)
    assert published["lane_count"] == 1
    assert published["planned_trace_count"] == 5
    assert len(list(args.campaign_dir.iterdir())) == 11
    args.command = "verify"
    assert cli.run(args)["valid"] is True
    (args.campaign_dir / f"{args.lane}.yml").write_bytes(b"changed predecessor")
    with pytest.raises(ValueError, match="predecessor"):
        cli.run(args)


def test_malformed_or_duplicate_spec_is_rejected(cli, tmp_path, monkeypatch):
    args, _ = _setup(tmp_path, monkeypatch)
    args.qualification_spec.write_text('{"schema_version":1,"schema_version":1,"qualification_sets":[]}')
    with pytest.raises(ValueError, match="duplicate JSON"):
        cli.run(args)
    assert not args.output.exists()


def test_amended_plan_binds_policy_bytes_and_distinct_cohort(cli, tmp_path, monkeypatch):
    from datetime import UTC, datetime
    from qcsd_lab import rapid_selection_amendment as amendment

    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, 14, tzinfo=UTC)

    monkeypatch.setattr(amendment, "datetime", FrozenClock)

    args, _ = _setup(tmp_path, monkeypatch)
    context = admission.load_admission_context(args.root)
    monkeypatch.setattr(amendment.profile, "FROZEN_V5_PROFILE_SHA256", _sha(context.profile_bytes))
    policy = amendment.build_selection_amendment(
        published_at_utc="2026-10-02T13:30:00Z",
        parent_profile_sha256=_sha(context.profile_bytes),
    )
    policy_raw = admission._json(policy)
    policy_path = args.root / "selection-amendment.json"
    policy_path.write_bytes(policy_raw)
    context.selection_amendment_bytes = policy_raw
    context.selection_amendment_sha256 = _sha(policy_raw)
    provenance_path = args.root / "provenance.json"
    provenance = admission._unpack(provenance_path.read_bytes(), admission.PROVENANCE_TYPE)
    provenance["inputs"]["selection_amendment"] = {
        "path": policy_path.name, "sha256": _sha(policy_raw),
    }
    provenance_path.write_bytes(admission._json(admission._bind(admission.PROVENANCE_TYPE, provenance)))
    context.provenance_sha256 = _sha(provenance_path.read_bytes())
    cohort = json.loads(args.cohort.read_bytes())
    cohort["receipt_type"] = amendment.AMENDED_COHORT_RECEIPT_TYPE
    cohort["payload"]["selection_amendment_sha256"] = _sha(policy_raw)
    args.cohort.write_text(json.dumps(cohort))
    assert cli.run(args)["planned_trace_count"] == 50
    args.command = "verify"
    assert cli.run(args)["valid"] is True
    policy_path.write_bytes(policy_raw + b"\n")
    with pytest.raises(ValueError, match="reference bytes changed"):
        cli.run(args)
