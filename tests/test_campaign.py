from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture import split_endpoint, tuple_filter
from qcsd_lab.capture_session import Defense, Limits, _runner_result_complete, _validate_run_binding
from qcsd_lab.orchestrator import (
    CampaignIncomplete,
    load_campaign,
    plan_campaign,
    preflight_campaign,
    run_campaign,
)
from qcsd_lab.util import load_json, sha256_file
from qcsd_lab.verification import verify_result


def _resource(
    identifier: int,
    url: str,
    *,
    depends_on: list[int] | None = None,
    headers: list[list[str]] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "url": url,
        "type": "Document" if identifier == 0 else "Other",
        "content_length": 64,
        "data_length": 64,
        "chaff_priority": identifier == 0,
        "known_valid": True,
        "depends_on": depends_on or [],
        "headers": headers or [],
    }


def _configuration(
    tmp_path: Path,
    *,
    workloads: dict[str, tuple[int, list[dict[str, Any]]]] | None = None,
    policies: list[str] | None = None,
    defenses: list[str | dict[str, Any]] | None = None,
    max_attempts: int = 2,
    profile: str = "live",
) -> Path:
    config = tmp_path / "config"
    campaign_dir = config / "campaigns"
    workload_dir = config / "workloads"
    campaign_dir.mkdir(parents=True)
    workload_dir.mkdir()
    workloads = workloads or {
        "alpha": (
            1,
            [_resource(0, "https://alpha.test/", headers=[["accept", "text/html"]])],
        )
    }
    visits: dict[str, int] = {}
    for identifier, (visit_count, resources) in workloads.items():
        visits[identifier] = visit_count
        (workload_dir / f"{identifier}.json").write_text(
            json.dumps({"resources": resources}, sort_keys=True),
            encoding="utf-8",
        )
    campaign = {
        "schema": 1,
        "name": "contract-test",
        "purpose": "smoke",
        "seed": 7_331,
        "profile": profile,
        "workloads": visits,
        "request_policies": policies or ["as-defined"],
        "defenses": defenses or ["undefended", "front"],
        "limits": {
            "timeout_seconds": 1,
            "max_response_bytes": 4096,
            "capture_seconds": 2,
            "capture_megabytes": 1,
            "max_attempts": max_attempts,
            "per_origin_cooldown_seconds": 0,
            "settle_seconds": 0,
        },
    }
    path = campaign_dir / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _write_successful_attempt(
    attempt: Path,
    workload_id: str,
    defense_name: str,
    *,
    body_sha256: str = "a" * 64,
) -> dict[str, Any]:
    captures = attempt / "captures"
    neqo = attempt / "neqo"
    captures.mkdir(parents=True)
    neqo.mkdir()
    (captures / "direct-quic.pcapng").write_bytes(
        b"controlled-capture:" + workload_id.encode() + b":" + defense_name.encode()
    )
    (neqo / "packets.csv").write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1,0,64,,unshaped,\n",
        encoding="utf-8",
    )
    (neqo / "events.csv").write_text(
        "monotonic_us,connection,event,phase,details\n",
        encoding="utf-8",
    )
    (neqo / "schedule.csv").write_text(
        "direction,satisfaction,miss_reason,size,observed_size\n",
        encoding="utf-8",
    )
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "responses": [
                    {
                        "resource_id": 0,
                        "status": 200,
                        "bytes": 64,
                        "body_sha256": body_sha256,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ],
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "192.0.2.1:50000",
                        "remote_address": "198.51.100.1:443",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "success": True,
        "views": [{"id": "direct-quic", "valid": True}],
        "offloads": [{"interface": "eth0", "verified": True}],
        "endpoint_count": 1,
        "endpoint_count_valid": True,
        "operationally_valid": True,
        "defense_diagnostics": (
            {}
            if defense_name == "undefended"
            else {
                "scheduled_incoming_requested_bytes": 0,
                "scheduled_incoming_consumed_bytes": 0,
                "scheduled_incoming_retired_bytes": 0,
                "scheduled_incoming_unresolved_bytes": 0,
            }
        ),
    }


def _write_pacing_miss(attempt: Path) -> None:
    (attempt / "neqo/schedule.csv").write_text(
        "direction,satisfaction,miss_reason,size,observed_size\noutgoing,missed,pacing,1200,\n",
        encoding="utf-8",
    )


class _Collector:
    def __init__(
        self,
        *,
        fail_once: set[str] | None = None,
        mismatched: set[str] | None = None,
    ) -> None:
        self.fail_once = fail_once or set()
        self.mismatched = mismatched or set()
        self.calls: list[tuple[str, str, int, Path]] = []
        self.counts: Counter[str] = Counter()

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.calls.append((workload_id, defense.name, seed, attempt))
        self.counts[defense.name] += 1
        if defense.name in self.fail_once and self.counts[defense.name] == 1:
            attempt.mkdir(parents=True)
            failure = {
                "stage": "runner",
                "type": "ControlledFailure",
                "message": "first attempt failed",
            }
            (attempt / "failure.json").write_text(
                json.dumps(failure, sort_keys=True), encoding="utf-8"
            )
            return {"success": False, "failure": failure}
        digest = "b" * 64 if defense.name in self.mismatched else "a" * 64
        return _write_successful_attempt(
            attempt,
            workload_id,
            defense.name,
            body_sha256=digest,
        )


class _PacingMissCollector:
    def __init__(self, miss_front_attempts: set[int]) -> None:
        self.miss_front_attempts = miss_front_attempts
        self.counts: Counter[str] = Counter()

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.counts[defense.name] += 1
        result = _write_successful_attempt(attempt, workload_id, defense.name)
        if defense.name == "front" and self.counts[defense.name] in self.miss_front_attempts:
            _write_pacing_miss(attempt)
        return result


def test_endpoint_parser_and_exact_filter_support_both_ip_versions() -> None:
    assert split_endpoint("172.17.0.2:50000") == ("172.17.0.2", 50000)
    assert split_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)
    display_filter = tuple_filter(
        [
            {
                "id": 0,
                "local_address": "172.17.0.2:50000",
                "remote_address": "203.0.113.1:443",
            },
            {
                "id": 1,
                "local_address": "[2001:db8::2]:50001",
                "remote_address": "[2001:db8::1]:443",
            },
        ]
    )
    assert "udp.srcport==50000" in display_filter
    assert "ip.src==172.17.0.2" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter


def test_capture_session_requires_a_complete_successful_runner_result() -> None:
    response = {"resource_id": 0, "complete": True, "outcome": "succeeded"}
    assert _runner_result_complete({"completion_status": "complete", "responses": [response]}, {0})
    assert not _runner_result_complete(
        {"completion_status": "partial", "responses": [response]}, {0}
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "complete": False, "outcome": "failed"}],
        },
        {0},
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [response],
            "defense_diagnostics": {"padding_event_guard_triggered": True},
        },
        {0},
    )
    assert not _runner_result_complete(
        {"completion_status": "complete", "responses": [response]}, {0, 1}
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [response, response],
        },
        {0, 1},
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "resource_id": 999}],
        },
        {0},
    )


def test_runner_receipt_is_bound_to_frozen_launch_inputs(tmp_path: Path) -> None:
    manifest = tmp_path / "workload.json"
    manifest.write_text('{"resources":[]}\n', encoding="utf-8")
    context = SimpleNamespace(
        request_policy="as-defined",
        udp_payload_ceiling=1200,
        limits=Limits(max_response_bytes=4096),
    )
    run = {
        "seed": 7,
        "request_policy": "as-defined",
        "workload_hash_sha256": sha256_file(manifest),
        "max_response_bytes": 4096,
        "resolved_configuration": {
            "max_udp_payload_size": 1200,
            "defense": {"kind": "none"},
        },
        "defense_parameters": None,
    }
    _validate_run_binding(
        run,
        manifest=manifest,
        workload_id="site",
        defense=Defense("undefended", "none", True),
        seed=7,
        context=context,
    )
    run["workload_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="frozen sample inputs"):
        _validate_run_binding(
            run,
            manifest=manifest,
            workload_id="site",
            defense=Defense("undefended", "none", True),
            seed=7,
            context=context,
        )


def test_expansion_is_deterministic_and_keeps_multi_origin_work_in_one_sample(
    tmp_path: Path,
) -> None:
    path = _configuration(
        tmp_path,
        workloads={
            "simple": (2, [_resource(0, "https://one.test/")]),
            "complex": (
                1,
                [
                    _resource(0, "https://one.test/"),
                    _resource(1, "https://one.test/app.js", depends_on=[0]),
                    _resource(3, "https://ONE.test:443/default.js", depends_on=[0]),
                    _resource(2, "https://two.test/lib.js", depends_on=[0]),
                ],
            ),
        },
        policies=["as-defined", "half-duplex"],
    )
    first = plan_campaign(load_campaign(path))
    second = plan_campaign(load_campaign(path))

    assert first == second
    assert len(first) == (2 + 1) * 2 * 2
    groups: list[tuple[str, str, int]] = []
    for sample in first:
        group = (sample["workload_id"], sample["request_policy"], sample["visit"])
        if not groups or groups[-1] != group:
            groups.append(group)
    assert groups == [
        ("simple", "as-defined", 0),
        ("simple", "as-defined", 1),
        ("simple", "half-duplex", 0),
        ("simple", "half-duplex", 1),
        ("complex", "as-defined", 0),
        ("complex", "half-duplex", 0),
    ]
    complex_workload = next(item for item in load_campaign(path).workloads if item.id == "complex")
    assert complex_workload.origin_count == 2
    assert all(sample["workload_id"] == "complex" for sample in first[-4:])
    assert len({sample["path"].split("/")[1] for sample in first[-4:]}) == 1

    preflight = preflight_campaign(path)
    assert preflight["valid"] is True
    assert preflight["sample_count"] == 12
    assert preflight["execution_order"] == [sample["sample_id"] for sample in first]
    assert next(item for item in preflight["workloads"] if item["id"] == "complex")["origins"] == 2


def test_resume_epoch_restarts_cooldown_for_previously_attempted_origins(tmp_path: Path) -> None:
    path = _configuration(tmp_path)
    campaign = load_campaign(path)
    samples = plan_campaign(campaign)
    samples[0]["attempts"] = 1

    history = orchestrator._prior_origin_completion(campaign, {"samples": samples})

    assert history.keys() == {"https://alpha.test"}
    assert all(value > 0 for value in history.values())


def test_campaign_accepts_only_the_exact_research_1200_profile_token(tmp_path: Path) -> None:
    path = _configuration(tmp_path, profile="research-1200")

    campaign = load_campaign(path)
    assert campaign.profile == "research-1200"
    assert campaign.udp_payload_ceiling == 1_200
    assert preflight_campaign(path)["valid"] is True

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    for invalid in ("research_1200", "research1200", "Research-1200"):
        value["profile"] = invalid
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match="campaign profile must be one of"):
            load_campaign(path)


@pytest.mark.parametrize(
    "obsolete",
    [
        {"monitored": {"alpha": 1}},
        {"unmonitored": {"alpha": 1}},
        {"split": {"train": 0.8}},
        {"classifier": "df"},
        {"header_policy": {"mode": "minimal"}},
    ],
)
def test_campaign_rejects_obsolete_dataset_and_header_policy_layers(
    tmp_path: Path, obsolete: dict[str, Any]
) -> None:
    path = _configuration(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value.update(obsolete)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_campaign(path)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("", "at least one packet"),
        ("not-a-record\n", "seconds,signed_size"),
        ("nan,1200\n", "finite and non-negative"),
        ("0,0\n", "must not be zero"),
        ("0,1201\n", "1200-byte QCSD profile ceiling"),
    ],
)
def test_campaign_preflight_rejects_invalid_static_schedules(
    tmp_path: Path, contents: str, message: str
) -> None:
    path = _configuration(
        tmp_path,
        defenses=[
            "undefended",
            {"name": "static", "kind": "static", "schedule": "schedule.csv", "mode": "chaff-only"},
        ],
    )
    (path.parent / "schedule.csv").write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        preflight_campaign(path)


def test_campaign_preflight_accepts_a_valid_static_schedule(tmp_path: Path) -> None:
    path = _configuration(
        tmp_path,
        defenses=[
            "undefended",
            {"name": "static", "kind": "static", "schedule": "schedule.csv", "mode": "chaff-only"},
        ],
    )
    (path.parent / "schedule.csv").write_text(
        "# seconds,signed_size\n0.000000,1200\n0.005000,-1200\n",
        encoding="utf-8",
    )

    assert preflight_campaign(path)["valid"] is True


def test_multi_defense_campaign_requires_one_response_baseline(tmp_path: Path) -> None:
    path = _configuration(tmp_path, defenses=["front", "tamaraw"])

    with pytest.raises(ValueError, match="requires one undefended baseline"):
        load_campaign(path)


@pytest.mark.parametrize("identifier", ["campaign", "workload", "defense"])
def test_preflight_rejects_unicode_identifiers_before_materializing_result(
    tmp_path: Path, identifier: str
) -> None:
    path = _configuration(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if identifier == "campaign":
        value["name"] = "café"
    elif identifier == "workload":
        value["workloads"] = {"café": 1}
    else:
        value["defenses"][1] = {"name": "frönt", "kind": "front"}
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem-safe"):
        run_campaign(path, tmp_path / "results")
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("front", "tamaraw"),
        ("front", "none"),
        ("undefended", "front"),
        ("traffic-morphing", "wtf-pad"),
    ],
)
def test_campaign_preflight_rejects_canonical_defense_bound_to_wrong_runtime(
    tmp_path: Path, name: str, kind: str
) -> None:
    path = _configuration(tmp_path, defenses=[{"name": name, "kind": kind}])

    with pytest.raises(ValueError, match=r"is not bound to runtime kind"):
        preflight_campaign(path)


def test_campaign_preflight_allows_custom_defense_alias_for_runtime_kind(tmp_path: Path) -> None:
    path = _configuration(
        tmp_path,
        defenses=["undefended", {"name": "front-experiment", "kind": "front"}],
    )

    campaign = load_campaign(path)
    assert [(defense.name, defense.kind) for defense in campaign.defenses] == [
        ("undefended", "none"),
        ("front-experiment", "front"),
    ]
    assert preflight_campaign(path)["valid"] is True


def test_run_writes_only_the_canonical_result_and_retains_failed_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    collector = _Collector(fail_once={"front"})
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    root = run_campaign(path, tmp_path / "results")
    verified = verify_result(root)
    experiment = verified.experiment

    assert experiment["status"] == "complete"
    assert experiment["summary"] == {
        "planned": 2,
        "accepted": 2,
        "failed": 0,
        "eligible": 2,
        "passed": True,
    }
    assert set(path.name for path in root.iterdir()) == {
        "experiment.json",
        "evidence.sha256",
        "inputs",
        "samples",
        "failures",
        "derived",
    }
    assert not list(root.rglob("sample.json"))
    assert not list(root.rglob("*.jsonl"))
    assert not list(root.rglob("qlog"))
    assert list((root / "derived").iterdir()) == []

    expected_artifacts = {
        "capture.pcapng",
        "neqo/run.json",
        "neqo/packets.csv",
        "neqo/events.csv",
        "neqo/schedule.csv",
    }
    for sample in experiment["samples"]:
        sample_root = root / sample["path"]
        actual = {
            artifact.relative_to(sample_root).as_posix()
            for artifact in sample_root.rglob("*")
            if artifact.is_file()
        }
        assert actual == expected_artifacts
        assert sample["diagnostics"]["response_match"] is True
        assert sample["eligible"] is True

    front = next(sample for sample in experiment["samples"] if sample["defense"] == "front")
    assert front["attempts"] == 2
    retained = root / "failures" / front["sample_id"] / "attempt-001/failure.json"
    assert load_json(retained)["message"] == "first attempt failed"
    assert not (retained.parents[1] / "attempt-002").exists()
    assert str(retained.relative_to(root)) in verified.checksums


def test_collection_success_with_pacing_miss_is_quarantined_then_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    collector = _PacingMissCollector({1})
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    root = run_campaign(path, tmp_path / "results")
    experiment = verify_result(root).experiment
    front = next(sample for sample in experiment["samples"] if sample["defense"] == "front")
    failed_attempt = root / "failures" / front["sample_id"] / "attempt-001"
    receipt = load_json(failed_attempt / "attempt.json")

    assert collector.counts == {"undefended": 1, "front": 2}
    assert front["state"] == "accepted"
    assert front["attempts"] == 2
    assert front["eligible"] is True
    assert receipt["success"] is False
    assert receipt["failure"]["stage"] == "fidelity"
    assert receipt["failure"]["type"] == "StrictDefenseFidelityFailure"
    assert receipt["failure"]["details"][0]["schedule"]["missed_events"] == 1
    assert (failed_attempt / "captures/direct-quic.pcapng").is_file()
    assert not list(root.rglob(".promotion"))
    assert not (failed_attempt.parent / "attempt-002").exists()


def test_all_collection_successes_with_fidelity_misses_end_terminally_without_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    collector = _PacingMissCollector({1, 2})
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    with pytest.raises(CampaignIncomplete) as raised:
        run_campaign(path, tmp_path / "results")

    root = raised.value.root
    experiment = verify_result(root).experiment
    front = next(sample for sample in experiment["samples"] if sample["defense"] == "front")

    assert collector.counts == {"undefended": 1, "front": 2}
    assert experiment["status"] == "incomplete"
    assert front["state"] == "failed"
    assert front["attempts"] == 2
    assert front["eligible"] is False
    assert front["failure"]["stage"] == "fidelity"
    assert not (root / front["path"]).exists()
    assert not list(root.rglob(".promotion"))
    for attempt_number in (1, 2):
        receipt = load_json(
            root / "failures" / front["sample_id"] / f"attempt-{attempt_number:03d}/attempt.json"
        )
        assert receipt["success"] is False
        assert receipt["failure"]["stage"] == "fidelity"


def test_paired_response_mismatch_makes_the_terminal_result_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path)
    collector = _Collector(mismatched={"front"})
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    with pytest.raises(CampaignIncomplete) as raised:
        run_campaign(path, tmp_path / "results")

    root = raised.value.root
    experiment = verify_result(root).experiment
    assert experiment["status"] == "incomplete"
    assert experiment["summary"]["passed"] is False
    baseline = next(sample for sample in experiment["samples"] if sample["baseline"])
    front = next(sample for sample in experiment["samples"] if sample["defense"] == "front")
    assert baseline["eligible"] is True
    assert baseline["diagnostics"]["response_match"] is True
    assert front["state"] == "accepted"
    assert front["attempts"] == 1
    assert front["eligible"] is False
    assert front["diagnostics"]["response_match"] is False
    assert collector.counts["front"] == 1


def test_materialization_uses_the_exact_campaign_bytes_that_were_parsed(
    tmp_path: Path,
) -> None:
    path = _configuration(tmp_path)
    campaign = load_campaign(path)
    validated_bytes = path.read_bytes()
    workload = campaign.workloads[0]
    validated_workload_bytes = workload.path.read_bytes()
    changed = yaml.safe_load(path.read_text(encoding="utf-8"))
    changed["purpose"] = "evaluation"
    changed["seed"] += 1
    path.write_text(yaml.safe_dump(changed, sort_keys=False), encoding="utf-8")
    workload.path.write_bytes(validated_workload_bytes + b"\n")

    root = tmp_path / "materialized"
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, {})

    assert (root / "inputs/campaign.yml").read_bytes() == validated_bytes
    frozen_workload = root / "inputs/workloads" / f"{workload.id}.json"
    assert frozen_workload.read_bytes() == validated_workload_bytes
    assert configuration["workloads"][0]["sha256"] == sha256_file(frozen_workload)
    assert runtime.purpose == "smoke"
    assert runtime.seed == 7_331
    assert configuration["campaign_sha256"] == sha256_file(root / "inputs/campaign.yml")
    assert not (root / "experiment.json").exists()


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        ("schedule", "Static schedule changed during input materialization"),
        ("parameters", "parameter artifact changed during input materialization"),
        ("provenance", "parameter artifact changed during input materialization"),
    ],
)
def test_materialization_rejects_artifact_copy_races_before_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    message: str,
) -> None:
    fixture_root = Path(__file__).parents[1] / "config/defense-params"
    if artifact == "schedule":
        defenses: list[str | dict[str, Any]] = [
            "undefended",
            {
                "name": "static-control",
                "kind": "static",
                "schedule": str(fixture_root / "static-control-1200.csv"),
                "mode": "chaff-only",
            },
        ]
    else:
        defenses = [
            "undefended",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": str(fixture_root / "traffic-morphing-live.json"),
            },
        ]
    campaign = load_campaign(
        _configuration(
            tmp_path / "source",
            workloads={
                "cloudflare-quiche": (
                    1,
                    [_resource(0, "https://cloudflare-quiche.test/")],
                )
            },
            defenses=defenses,
        )
    )
    if artifact == "schedule":
        defense = next(item for item in campaign.defenses if item.kind == "static")
        target = defense.schedule_path
    else:
        defense = next(item for item in campaign.defenses if item.kind == "traffic_morphing")
        target = (
            defense.parameters_path
            if artifact == "parameters"
            else defense.parameters_provenance_path
        )
    assert target is not None
    original_copy = orchestrator.shutil.copy2

    def corrupting_copy(source: Path, destination: Path) -> Path:
        copied = original_copy(source, destination)
        if Path(source).resolve() == target.resolve():
            Path(destination).write_bytes(b"changed-after-validation\n")
        return Path(copied)

    monkeypatch.setattr(orchestrator.shutil, "copy2", corrupting_copy)
    root = tmp_path / "materialized"

    with pytest.raises(ValueError, match=message):
        orchestrator._materialize_inputs(root, campaign, {})
    assert not (root / "experiment.json").exists()
