"""Serial public launch ownership with real plan, intent and raw fence code.

The existing tiny fixtures substitute admission, named120 and canary scientific
success. Docker, host execution and deep physical completion are explicit HOST
boundaries. These cases assert no installed pass or accepted physical trace.
"""
from copy import deepcopy
from pathlib import Path
import json
import subprocess

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_operation_facts as operations
from tools import rapid_rolling_capture as cli
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_rolling_capture import rolling_setup
from tests.test_rapid_operation_facts import scheduled
from tests.test_rapid_runtime_inspector import operation_context_case
from tests.test_supplied_static_get import actual_contract_fixture
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_capture_amendment import original
from tests.test_static_budget_successor import budget_fixture


@pytest.fixture
def serial_case(operation_context_case, rolling_setup, monkeypatch):
    case = operation_context_case
    payload = lanes._payload(case.spec.plan_receipt, lanes.PLAN_TYPE)
    proof = deepcopy(rolling_setup.base.proof)
    proof.update(plan_payload=payload, plan_receipt_sha256=rolling._ref(case.spec.plan_receipt)["sha256"],
        bindings=payload["bindings"], sites=payload["sites"], cohort_generation=payload["cohort_generation"],
        acquisition_provenance_sha256=payload["acquisition_provenance_sha256"])
    case.image_calls, case.host_calls, case.deep_calls, case.owners = [], [], [], []
    case.inject_before_image = case.inject_after_intent = case.inject_after_host = case.inject_after_deep = None

    def image(command, **kwargs):
        assert command[0] == "docker" and "none" in command
        case.image_calls.append(command)
        case.owners.append(operations.current_context())
        if case.inject_before_image:
            case.inject_before_image()
        return subprocess.CompletedProcess(command, 0, json.dumps(proof), "")
    monkeypatch.setattr(lanes.subprocess, "run", image)
    original_intent = lanes.prepare_lane_intent
    def intent(*args, **kwargs):
        result = original_intent(*args, **kwargs)
        if case.inject_after_intent:
            case.inject_after_intent()
        return result
    monkeypatch.setattr(lanes, "prepare_lane_intent", intent)
    def host(spec, root, directory, command, environment, lock):
        case.host_calls.append(command)
        assert operations.current_context() is case.owners[-1]
        value = json.loads(environment["QCSD_RAPID_ROLLING_LAUNCH_INPUT"])
        assert value["intent_sha256"] == rolling._ref(directory / "intent.json")["sha256"]
        assert value["readiness_mount_roots"]
        lanes._create(root, directory / "host-process.json", lanes.PROCESS_TYPE, {"returncode": 0})
        if case.inject_after_host:
            case.inject_after_host()
    monkeypatch.setattr(lanes, "_actuate_host", host)
    def deep(spec, root, target, *, complete, _context=None):
        case.deep_calls.append(target)
        assert complete and _context is operations.current_context() is case.owners[-1]
        rolling.verify_capture_plan(spec, _context=_context)
        rolling.readiness_roots(spec, case.lane.campaign_name, _context=_context)
        _context.check()
        receipt = target.parent / "engineering-deep-boundary.json"
        receipt.write_bytes(b"explicit HOST physical-completion boundary\n")
        if case.inject_after_deep:
            case.inject_after_deep()
        return {"receipt": str(receipt)}
    monkeypatch.setattr(rolling, "check_lane_in_image", deep)
    case.args = cli._parser().parse_args(["launch", "--spec", str(case.root / "serial-spec.json"),
        "--evidence-root", str(case.root), "--lane", case.lane.campaign_name])
    rolling._write_spec(case.args.spec, case.spec)
    return case


def test_real_public_serial_launch_shares_one_owner_and_keeps_intent_image_guards(serial_case):
    case = serial_case
    parent = operations.OperationFacts()
    with parent.scope():
        result = cli.run(case.args)
        assert operations.current_context() is parent
    assert Path(result["receipt"]).is_file()
    assert len(case.image_calls) == len(case.host_calls) == len(case.deep_calls) == 1
    assert case.owners[0] is not parent and case.owners[0] is not None
    assert case.counts["qualification"] == case.counts["canary"] == 1
    assert operations.current_context() is None
    intent = lanes._payload(case.root / "lanes" / case.lane.campaign_name / "intent.json", lanes.INTENT_TYPE)
    assert intent["actuator"] == "run" and intent["generation"] == 1 and intent["scientific_credit"] is False


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_launch_raw_changes_after_intent_refuse_before_host(serial_case, mutation):
    case = serial_case
    def changed():
        source = case.dependencies.canary_source
        target = source / "src/measurement.py"
        if mutation == "bytes":
            target.write_bytes(target.read_bytes() + b"changed before host\n")
        elif mutation == "mode":
            target.chmod(target.stat().st_mode ^ 0o040)
        else:
            (source / "extra-member").write_bytes(b"changed complete membership\n")
    case.inject_after_intent = changed
    with pytest.raises(ValueError, match="changed"):
        cli.run(case.args)
    assert case.image_calls and not case.host_calls and not case.deep_calls
    assert operations.current_context() is None


def test_launch_success_closes_raw_again_after_physical_boundary(serial_case):
    case = serial_case
    case.inject_after_deep = lambda: case.dependencies.canary_recipe.write_bytes(b"changed after deep boundary\n")
    with pytest.raises(ValueError, match="changed"):
        cli.run(case.args)
    assert len(case.host_calls) == len(case.deep_calls) == 1
    assert operations.current_context() is None


def test_direct_launch_borrows_explicit_owner_and_restores_parent(serial_case):
    case = serial_case
    parent, owner = operations.OperationFacts(), operations.OperationFacts()
    with parent.scope():
        result = lanes.launch_lane(case.spec, case.root, case.lane.campaign_name, _context=owner)
        assert operations.current_context() is parent
    assert result.is_file() and case.owners == [owner]
    owner.check()


def test_each_public_launch_has_a_fresh_owner(serial_case):
    case = serial_case
    assert cli.run(case.args)["receipt"]
    payload = lanes._payload(case.spec.plan_receipt, lanes.PLAN_TYPE)
    other = next(row for row in payload["lanes"] if row["mode"] == "undefended"
                 and row["campaign_name"] != case.lane.campaign_name)
    case.lane = lanes._lane({"plan_payload": payload}, other["campaign_name"])
    case.args.lane = case.lane.campaign_name
    assert cli.run(case.args)["receipt"]
    assert len(case.owners) == 2 and case.owners[0] is not case.owners[1]
    assert case.counts["qualification"] == case.counts["canary"] == 2


def test_changed_raw_during_command_generation_refuses_before_docker(serial_case, monkeypatch):
    case = serial_case
    original = lanes.image_check_command
    def command(*args, **kwargs):
        value = original(*args, **kwargs)
        case.dependencies.canary_recipe.write_bytes(b"changed before independent image call\n")
        return value
    monkeypatch.setattr(lanes, "image_check_command", command)
    with pytest.raises(ValueError, match="changed"):
        cli.run(case.args)
    assert not case.image_calls and not case.host_calls
    assert not (case.root / "lanes" / case.lane.campaign_name).exists()


def test_enrollment_reuses_only_same_action_and_still_reopens_raw(serial_case, monkeypatch):
    case = serial_case
    actual = rolling.verify_policy
    calls = []
    def policy(root):
        calls.append(root)
        return actual(root)
    monkeypatch.setattr(rolling, "verify_policy", policy)
    contexts = [operations.OperationFacts(), operations.OperationFacts()]
    for context in contexts:
        with context.scope():
            first = rolling._verify_enrollment(case.spec.cohort)
            verified = {}
            assert rolling._verify_enrollment(case.spec.cohort, _verified=verified) == first
            assert verified[case.spec.cohort.absolute()][1:] == first[:2]
        context.check()
    assert len(calls) == 2
    case.spec.cohort.write_bytes(case.spec.cohort.read_bytes() + b"\n")
    with contexts[-1].scope(), pytest.raises(ValueError, match="changed"):
        rolling._verify_enrollment(case.spec.cohort)


def test_installed_completion_command_passes_the_same_explicit_owner(serial_case, monkeypatch):
    case, owner = serial_case, operations.OperationFacts()
    calls = []
    actual = lanes.image_check_command
    def command(spec, **kwargs):
        calls.append(kwargs.get("_context"))
        return actual(spec, **kwargs)
    monkeypatch.setattr(lanes, "image_check_command", command)
    with owner.scope():
        argv = rolling.lane_check_command(case.spec, case.root,
            case.root / "lanes" / case.lane.campaign_name / "intent.json", complete=True, _context=owner)
    owner.check()
    assert calls == [owner] and argv[0] == "docker" and "none" in argv
    assert str(case.root) + ":" + str(case.root) + ":rw" in argv


def test_memoized_enrollment_restores_every_authenticated_parent(rolling_setup):
    first = rolling.enroll(rolling_setup.root)
    rolling_setup.status["terminal_prefix"] = rolling_setup.terminals[:2]
    second = rolling.enroll(rolling_setup.root)
    owner = operations.OperationFacts()
    with owner.scope():
        expected = rolling._verify_enrollment(second)
        restored = {}
        assert rolling._verify_enrollment(second, _verified=restored) == expected
        assert set(restored) == {first.absolute(), second.absolute()}
        assert restored[first.absolute()][1]["ordinal"] == 1
        assert restored[second.absolute()][1]["ordinal"] == 2
    owner.check()


@pytest.mark.parametrize("target_name,mutation", [("intent.json", "mode"), ("lineage.json", "bytes")])
def test_new_intent_and_lineage_changes_refuse_before_host(serial_case, monkeypatch, target_name, mutation):
    case = serial_case
    original = rolling.readiness_roots
    def roots(*args, **kwargs):
        result = original(*args, **kwargs)
        target = case.root / "lanes" / case.lane.campaign_name / target_name
        if target.exists():
            if mutation == "bytes":
                target.write_bytes(target.read_bytes() + b"\n")
            else:
                target.chmod(target.stat().st_mode ^ 0o040)
        return result
    monkeypatch.setattr(rolling, "readiness_roots", roots)
    with pytest.raises(ValueError, match="changed"):
        cli.run(case.args)
    assert case.image_calls and not case.host_calls


def test_enrollment_memo_keeps_complete_original_get_raw_as_dependency(original):
    owner = operations.OperationFacts()
    with owner.scope():
        result = rolling._verify_enrollment(original.enrollment)
        assert rolling._verify_enrollment(original.enrollment) == result
    owner.check()
    raw = original.get_root / "native/packets.csv"
    raw.write_bytes(raw.read_bytes() + b"changed original admitted GET raw\n")
    with pytest.raises(ValueError, match="changed"):
        owner.check()


def test_deferred_wrapper_memo_fences_genuine_child_get_raw(rolling_setup, budget_fixture, monkeypatch):
    # The original deferral uses the unchanged producer and tiny Native emitter
    # fixture. Only the outer rolling admission primitive is substituted, as in
    # rolling_setup; no budget admission or installed success is asserted.
    from qcsd_lab import supplied_static_admission as static
    from qcsd_lab import rapid_site_admission as admission
    context, get_root, _ = budget_fixture
    completed_path = get_root / "native-completed.json"
    completed = lanes._load(lanes._read(completed_path))
    completed["returncode"] = 1
    completed_path.write_bytes(admission._json(completed))
    child = static.record_get_deferral(context.original, 53, get_root)
    parent = admission._child(rolling_setup.context.root, rolling_setup.terminals[0])
    envelope = lanes._load(lanes._read(parent))
    envelope["payload"]["facts"]["outcome"] = "deferred"
    envelope["payload"]["original_terminal"] = rolling._ref(child)
    parent.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE, envelope["payload"])))
    rolling_setup.terminals[0] = admission.evidence_reference(rolling_setup.context.root, parent)
    rolling_setup.status["terminal_prefix"] = rolling_setup.terminals[:2]
    policy = admission._unpack(lanes._read(rolling_setup.root / "policy.json"), rolling.POLICY_TYPE)
    monkeypatch.setattr(admission, "_now", lambda: policy["published_at"])
    enrollment = rolling.enroll(rolling_setup.root)
    owner = operations.OperationFacts()
    with owner.scope():
        expected = rolling._verify_enrollment(enrollment)
        assert rolling._verify_enrollment(enrollment) == expected
    owner.check()
    raw = get_root / "native/packets.csv"
    raw.write_bytes(raw.read_bytes() + b"changed genuine deferred child GET raw\n")
    with pytest.raises(ValueError, match="changed"):
        owner.check()
