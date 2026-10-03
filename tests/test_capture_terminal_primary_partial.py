"""V12 admits one physically owned FIN split; raw misses remain visible."""
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity, prepare
from qcsd_lab import rapid_selection_amendment as amendment, rapid_site_admission as admission
from tests.test_capture_tamaraw_policy import fixture as tam_fixture, save as tam_save, preparation
from tests.test_capture_buflo_ack_start import fixture as buflo_fixture, save as buflo_save, write_csv
from tests.test_rapid_primary_document_admission import _prepared_variable_workload
from tests.test_rapid_site_admission import Backend, _amended_context, _auto_page, _root_logs, context


def marker(cell=1200):
    return {"schema_version":1,"source":"bound-preparation-v1","policy":policy.TERMINAL_PRIMARY_POLICY,
        "cell_size":cell,"maximum_partial_cells":1,"primary_resource_index":0,"require_unique_stream":True,
        "require_fin":True,"require_nonempty_successful_primary":True,"require_full_advertisement":True,
        "require_exact_positive_split":True,"retired_credit_reassignment":False}


def partial_fixture(root, mode="tamaraw"):
    if mode == "buflo":
        native, events, rows = buflo_fixture(root)
        packets = None
    else:
        native, rows, packets = tam_fixture(root)
        events = []
    cell = 600 if mode == "cs_buflo" else 1200
    if mode == "cs_buflo":
        native.pop(policy.TAMARAW_FIELD)
        native["resolved_configuration"]["defense"] = {"kind":"cs_buflo","parameters":"cs.json"}
        for row in rows:
            if row["direction"] == "incoming": row["size"] = row["desired_udp_bytes"] = "600"
    native[policy.TERMINAL_PRIMARY_FIELD] = marker(cell)
    native["resolved_configuration"].update(initial_max_stream_data=16,max_stream_data_excess=1000,max_udp_payload_size=1200,drop_unsatisfied_events=False)
    row = next(row for row in rows if row["direction"] == "incoming")
    target, slot = int(row["target_time_us"]), int(row["slot_id"])
    fin, adv = target+500, target+1100
    consumed = 550 if mode == "cs_buflo" else cell//2
    proof = {"schema_version":1,"source":policy.TERMINAL_PRIMARY_PROOF_SOURCE,"policy":policy.TERMINAL_PRIMARY_POLICY,
        "resource_id":0,"endpoint":3,"stream":0,"slot":slot,"target_us":target,"cell_bytes":cell,
        "requested_bytes":cell,"advertised_bytes":cell,"consumed_bytes":consumed,"retired_bytes":cell-consumed,
        "fin_at_us":fin,"status":200,"body_bytes":100}
    native.update(completion_status="complete",error=None,responses=[{"resource_id":0,"status":200,"bytes":100,"complete":True}])
    native[policy.TERMINAL_PRIMARY_PROOF_FIELD] = proof
    n=sum(row["direction"]=="incoming" for row in rows)
    native.setdefault("defense_diagnostics",{}).update(scheduled_incoming_requested_bytes=n*cell,
        scheduled_incoming_advertised_bytes=n*cell,scheduled_incoming_consumed_bytes=n*cell-proof["retired_bytes"],
        scheduled_incoming_retired_bytes=proof["retired_bytes"],scheduled_incoming_unresolved_bytes=0)
    if mode == "buflo": native["defense_diagnostics"]["buflo_missed_incoming_cells"]=1
    if mode == "cs_buflo": native["defense_diagnostics"]["cs_buflo_runtime_udp_packet_size_bytes"]=600
    row.update(connection="3",satisfaction="missed",miss_reason="ReceiveCreditRetired",
        credit_consumed_at_us="",credit_consumption_delay_us="",terminal_defense_elapsed_us=str(fin),
        credit_advertised_at_us=str(adv),credit_advertisement_delay_us="100",send_policy="",desired_udp_bytes="")
    sequence=100
    def event(kind, detail, us, outcome):
        events.append({"monotonic_us":str(us),"connection":"3","event":kind,"outcome":outcome,"details":json.dumps(detail)})
    def observation(kind, at, **kwargs):
        nonlocal sequence
        detail={"type":kind,"endpoint":3,"stream":0,"production_sequence":sequence,"production_monotonic_ns":at*1000,**kwargs}
        sequence+=1
        event("observation",detail,at,"recorded")
    event("application_request",0,target+1001,"started")
    observation("stream_opened",target+1002,role="application")
    opened=json.loads(events[-1]["details"])
    event("terminal_primary_stream_binding",{"schema_version":1,"source":"native-dispatched-primary-resource-stream-v1",
        "resource_id":0,"endpoint":3,"stream":0,"production_sequence":opened["production_sequence"],
        "production_monotonic_ns":opened["production_monotonic_ns"],
        "observation":{key:value for key,value in opened.items() if key not in {"production_sequence","production_monotonic_ns"}}},target+1002,"bound")
    event("action",{"type":"configure_manual_receive","endpoint":3,"stream":0,"initial_limit":16},target+1003,"applied")
    event("action",{"type":"lease_parser_receive","endpoint":3,"stream":0,"absolute_limit":16+cell,"increase":cell,
        "owner":{"slot":slot,"packet":{"timestamp_us":target,"direction":"incoming","length":cell}}},target+1004,"applied")
    observation("receive_limit_advertised",adv,absolute_limit=16+cell,slot=None)
    observation("response_headers",target+1200,status=200,frame_bytes=16+consumed-103,content_length=None)
    observation("bytes_read",target+1300,bytes=16+consumed)
    observation("data_frame",target+1400,frame_header_bytes=3,data_bytes=100)
    observation("stream_finished",980+fin,finish="fin")
    finished=json.loads(events[-1]["details"])
    event("terminal_primary_fin_reduction",{"schema_version":1,"source":"native-controller-defense-elapsed-us-v1",
        "production_sequence":finished["production_sequence"],"production_monotonic_ns":finished["production_monotonic_ns"],
        "controller_defense_elapsed_us":fin,
        "observation":{key:value for key,value in finished.items() if key not in {"production_sequence","production_monotonic_ns"}}},980+fin,"controller_reduced")
    event("terminal_primary_partial_cell",proof,980+fin,"partial")
    save_partial(root,native,events,rows,packets)
    return native,events,rows,packets


def save_partial(root,native,events,rows,packets):
    if packets is not None:
        tam_save(root,native,rows,packets)
        write_csv(root/"events.csv",("monotonic_us","connection","event","outcome","details"),events)
    else: buflo_save(root,native,events,rows)


@pytest.mark.parametrize("mode",["tamaraw","buflo","cs_buflo"])
def test_actual_short_fin_reopens_owned_full_advertisement_and_retired_split(tmp_path,mode):
    native,events,rows,packets=partial_fixture(tmp_path,mode)
    source={"preparation":{**preparation(),policy.TERMINAL_PRIMARY_FIELD:policy.TERMINAL_PRIMARY_POLICY}}
    policy.validate_terminal_primary_source_binding(source,native,runner_directory=tmp_path)
    metrics=fidelity._schedule_realization_metrics_from_path(tmp_path/"schedule.csv")
    assert metrics["missed_events"]==1 and metrics["missed_event_reasons"]=={"ReceiveCreditRetired":1}
    assert metrics["terminal_primary_partial_cells"]==1
    assert metrics["incoming_credit_consumed_events"]==metrics["scheduled_incoming_events"]-1
    if mode != "cs_buflo":
        assert fidelity.fidelity_eligible(mode,native["defense_diagnostics"],sample_eligible=True,
            missed_events=1,outgoing_size_mismatches=0,schedule_metrics=metrics,
            resolved_configuration=native["resolved_configuration"],require_defense_activation=True)
    altered=deepcopy(metrics);altered.pop("terminal_primary_partial_events_sha256")
    assert not fidelity.fidelity_eligible(mode,native["defense_diagnostics"],sample_eligible=True,
        missed_events=1,outgoing_size_mismatches=0,schedule_metrics=altered,resolved_configuration=native["resolved_configuration"])


@pytest.mark.parametrize("mutation",["wrong-resource","no-fin","duplicate-partial","forged-sum","no-advertisement",
    "wrong-owner","foreign-stream","wrong-primary","wrong-cell","wrong-fin-clock","duplicate-source-sequence",
    "no-source","another-miss","fake-full-consumption","retired-reassigned",
    "missing-fin-reduction","wrong-reduction","wrong-stream-binding","future-production"])
def test_terminal_split_cannot_promote_invalid_physical_or_primary_evidence(tmp_path,mutation):
    native,events,rows,packets=partial_fixture(tmp_path)
    proof=native[policy.TERMINAL_PRIMARY_PROOF_FIELD]
    if mutation=="wrong-resource": proof["resource_id"]=1
    elif mutation=="no-fin": events=[event for event in events if not isinstance(json.loads(event["details"]),dict) or json.loads(event["details"]).get("type")!="stream_finished"]
    elif mutation=="duplicate-partial": events.append(deepcopy(events[-1]))
    elif mutation=="forged-sum": proof["consumed_bytes"]+=1
    elif mutation=="no-advertisement": events=[event for event in events if not isinstance(json.loads(event["details"]),dict) or json.loads(event["details"]).get("type")!="receive_limit_advertised"]
    elif mutation in {"wrong-owner","foreign-stream","duplicate-source-sequence"}:
        event=next(event for event in events if isinstance(json.loads(event["details"]),dict) and json.loads(event["details"]).get("type")==({"wrong-owner":"lease_parser_receive","foreign-stream":"lease_parser_receive","duplicate-source-sequence":"stream_finished"}[mutation]))
        detail=json.loads(event["details"])
        if mutation=="wrong-owner": detail["owner"]["slot"]+=1
        elif mutation=="foreign-stream": detail["stream"]=4
        else: detail["production_sequence"]=100
        event["details"]=json.dumps(detail)
    elif mutation=="wrong-primary":native["responses"][0]["complete"]=False
    elif mutation=="wrong-cell":proof["advertised_bytes"]-=1
    elif mutation=="wrong-fin-clock":proof["fin_at_us"]+=1
    elif mutation=="no-source":native.pop(policy.TERMINAL_PRIMARY_FIELD)
    elif mutation=="another-miss":rows[101].update(satisfaction="missed",miss_reason="ReceiveCreditRetired",credit_consumed_at_us="",credit_consumption_delay_us="")
    elif mutation=="fake-full-consumption":rows[100].update(satisfaction="satisfied",credit_consumed_at_us="1500",credit_consumption_delay_us="500")
    elif mutation=="missing-fin-reduction":events=[event for event in events if event["event"]!="terminal_primary_fin_reduction"]
    elif mutation in {"wrong-reduction","wrong-stream-binding","future-production"}:
        event=next(event for event in events if event["event"]==("terminal_primary_stream_binding" if mutation=="wrong-stream-binding" else "terminal_primary_fin_reduction"))
        detail=json.loads(event["details"])
        if mutation=="wrong-stream-binding":detail["resource_id"]=1
        elif mutation=="wrong-reduction":detail["controller_defense_elapsed_us"]-=1
        else:detail["production_monotonic_ns"]+=1000000
        event["details"]=json.dumps(detail)
    else:native["defense_diagnostics"]["scheduled_incoming_retired_bytes"]=0
    save_partial(tmp_path,native,events,rows,packets)
    with pytest.raises(ValueError):fidelity._schedule_realization_metrics_from_path(tmp_path/"schedule.csv")


@pytest.mark.parametrize("key,bad",[("schema_version",True),("cell_size",1200.0),("source","unbound"),
    ("maximum_partial_cells",2),("require_fin",False),("retired_credit_reassignment",True)])
def test_terminal_marker_exact_closed_contract(key,bad):
    value=marker();value[key]=bad
    with pytest.raises(ValueError):policy.validate_terminal_primary_capture_marker(value,cell_size=1200)


def test_terminal_partial_allows_actual_informational_headers_and_trailers(tmp_path):
    native,events,rows,packets=partial_fixture(tmp_path)
    first=next(index for index,event in enumerate(events) if isinstance(json.loads(event["details"]),dict)
        and json.loads(event["details"]).get("type")=="response_headers")
    interim=deepcopy(events[first]);detail=json.loads(interim["details"])
    detail.update(status=103,frame_bytes=3,production_monotonic_ns=1180000)
    interim.update(monotonic_us="1180",details=json.dumps(detail));events.insert(first,interim)
    fin=next(index for index,event in enumerate(events) if isinstance(json.loads(event["details"]),dict)
        and json.loads(event["details"]).get("type")=="stream_finished")
    trailer=deepcopy(interim);detail=json.loads(trailer["details"])
    detail.update(status=None,frame_bytes=3,production_monotonic_ns=1450000)
    trailer.update(monotonic_us="1450",details=json.dumps(detail));events.insert(fin,trailer)
    read=deepcopy(trailer);detail=json.loads(read["details"])
    detail={"type":"bytes_read","endpoint":3,"stream":0,"bytes":6,"production_monotonic_ns":1460000}
    read.update(monotonic_us="1460",details=json.dumps(detail));events.insert(fin+1,read)
    sequence=100;finished=None
    for event in events:
        if event["event"]!="observation":continue
        detail=json.loads(event["details"]);detail["production_sequence"]=sequence;sequence+=1
        event["details"]=json.dumps(detail)
        if detail["type"]=="stream_finished":finished=detail
    reduction=next(event for event in events if event["event"]=="terminal_primary_fin_reduction")
    detail=json.loads(reduction["details"]);detail["production_sequence"]=finished["production_sequence"]
    reduction["details"]=json.dumps(detail)
    proof=native[policy.TERMINAL_PRIMARY_PROOF_FIELD];proof["consumed_bytes"]+=6;proof["retired_bytes"]-=6
    native["defense_diagnostics"]["scheduled_incoming_consumed_bytes"]+=6
    native["defense_diagnostics"]["scheduled_incoming_retired_bytes"]-=6
    events[-1]["details"]=json.dumps(proof)
    save_partial(tmp_path,native,events,rows,packets)
    assert policy.validate_terminal_primary_partial_evidence(native,runner_directory=tmp_path)["terminal_primary_partial_consumed_bytes"]==606


def test_v12_declaration_inherits_exact_v11_and_16000_grid():
    value=amendment.build_selection_amendment(published_at_utc=datetime.now(UTC).isoformat().replace("+00:00","Z"),revision=12)
    payload=amendment.validate_selection_amendment(value)
    assert payload[policy.TERMINAL_PRIMARY_FIELD]==policy.TERMINAL_PRIMARY_POLICY
    assert payload["parent_selection_amendment_sha256"]==amendment.FROZEN_V11_AMENDMENT_SHA256
    assert payload[policy.FRONT_FIELD]==policy.FRONT_POLICY
    assert payload["cohort_contracts"][-1]["formal_sample_target"]==16000
    assert payload["terminal_primary_partial_cell_acceptance"]["maximum_partial_cells_per_complete_run"]==1
    fixed_path=Path(__file__).resolve().parents[1]/"config/curated-sources/crux73-tranco600-rapid-v5-selection-v12.json"
    fixed=json.loads(fixed_path.read_bytes())
    assert amendment.build_selection_amendment(published_at_utc=fixed["payload"]["published_at_utc"],revision=12)==fixed
    assert amendment.selection_amendment_sha256(fixed)==admission._sha(fixed_path.read_bytes())


@pytest.mark.parametrize("bad",[None,True,{},"unknown"])
def test_terminal_policy_present_malformed_is_not_legacy(bad):
    value={**preparation(),policy.TERMINAL_PRIMARY_FIELD:bad}
    with pytest.raises(ValueError):policy.validate_terminal_primary_preparation_policy(value)


def test_v12_source_marker_and_other_modes_stay_bound(tmp_path):
    native,*_=partial_fixture(tmp_path)
    source={"preparation":{**preparation(),policy.TERMINAL_PRIMARY_FIELD:policy.TERMINAL_PRIMARY_POLICY}}
    with pytest.raises(ValueError):policy.validate_terminal_primary_source_binding({},native)
    no_marker=deepcopy(native);no_marker.pop(policy.TERMINAL_PRIMARY_FIELD)
    with pytest.raises(ValueError):policy.validate_terminal_primary_source_binding(source,no_marker)
    for mode in ("none","front"):
        current=deepcopy(no_marker);current.pop(policy.TERMINAL_PRIMARY_PROOF_FIELD)
        current["resolved_configuration"]["defense"]["kind"]=mode
        policy.validate_terminal_primary_source_binding(source,current)
        current[policy.TERMINAL_PRIMARY_FIELD]=marker()
        with pytest.raises(ValueError):policy.validate_terminal_primary_source_binding(source,current)


def test_cs_partial_preserves_actual_full_advertisement_and_minimum_interval_counters(tmp_path,monkeypatch):
    from tests import test_buflo_study as existing
    captured=[]
    class Captured(Exception): pass
    def capture(*args,**kwargs):
        captured.append((args,kwargs));raise Captured
    original=existing.fidelity_eligible
    monkeypatch.setattr(existing,"fidelity_eligible",capture)
    with pytest.raises(Captured): existing.test_cs_buflo_fidelity_reconciles_typed_composition_and_rate_state()
    monkeypatch.setattr(existing,"fidelity_eligible",original)
    args,kwargs=captured[0]
    diagnostics=deepcopy(args[1]);schedule=deepcopy(kwargs["schedule_metrics"])
    root=tmp_path/"raw";root.mkdir()
    native,*_=partial_fixture(root,"cs_buflo")
    raw=policy.validate_terminal_primary_partial_evidence(native,runner_directory=root)
    diagnostics.update(scheduled_incoming_consumed_bytes=550,scheduled_incoming_retired_bytes=50,
        cs_buflo_realized_incoming_credit_bytes=550,cs_buflo_missed_incoming_cells=1,
        cs_buflo_incoming_termination_accounted_bytes=550,cs_buflo_incoming_last_termination_increment_bytes=550,
        cs_buflo_incoming_minimum_interval_opportunities=1,cs_buflo_incoming_minimum_interval_terminal=1,
        cs_buflo_incoming_minimum_interval_local_realized=1,cs_buflo_incoming_minimum_interval_full=0)
    schedule.update(raw,missed_events=1,missed_event_reasons={"ReceiveCreditRetired":1},
        terminal_satisfactions={"full":1,"partial":1,"missed":1},incoming_credit_advertised_events=0,
        incoming_credit_consumed_events=0)
    kwargs.update(missed_events=1,schedule_metrics=schedule)
    assert fidelity.fidelity_eligible(args[0],diagnostics,**kwargs)
    # The full advertisement remains600, while actual consumption is550.
    assert diagnostics["scheduled_incoming_advertised_bytes"]==600
    assert diagnostics["scheduled_incoming_consumed_bytes"]==550
    diagnostics["cs_buflo_missed_incoming_cells"]=2
    assert not fidelity.fidelity_eligible(args[0],diagnostics,**kwargs)


def test_v12_final50_cohort_and_planner_bind_new_and_inherited_policies(tmp_path,monkeypatch):
    from tests import test_rapid_selection_amendment as fixtures
    from tests.test_rapid_capture_plan import _sites
    from qcsd_lab import rapid_capture_plan as plan
    current=fixtures.context_v2.__wrapped__(fixtures.context.__wrapped__(tmp_path,monkeypatch))
    current["amendment"]=fixtures._receipt(revision=12)
    digest=amendment.selection_amendment_sha256(current["amendment"])
    now=datetime.now(UTC).isoformat().replace("+00:00","Z")
    for facts in current["records"].values():
        if facts["admission"] is None:continue
        facts["automated_site_screen"].update(selection_amendment_sha256=digest,screened_at=now)
        facts["admission"].update(application_response_policy="completed-terminal-http-errors-v1",
            terminal_http_error_resource_ids=[],application_response_evidence_sha256="c"*64,
            primary_document_identity_policy="variable-primary-document-body-v1",
            qualified_chaff_origin_policy="prepared-approved-origins-v1",
            buflo_incoming_credit_release_policy=policy.ACK_START_POLICY,
            tamaraw_capture_policy=policy.TAMARAW_POLICY,front_capture_policy=policy.FRONT_POLICY,
            terminal_primary_partial_cell_policy=policy.TERMINAL_PRIMARY_POLICY)
    cohort=fixtures._build(current)
    assert cohort["payload"][policy.TERMINAL_PRIMARY_FIELD]==policy.TERMINAL_PRIMARY_POLICY
    assert len(cohort["payload"]["selected_candidate_ids"])==50
    assert cohort["payload"]["formal_sample_target"]==16000
    lanes=plan.plan_lanes(_sites(50),final=True)
    assert len(lanes)==800 and sum(lane.sample_count for lane in lanes)==16000
    admitted=next(facts["admission"] for facts in current["records"].values() if facts["admission"] is not None)
    for key in (policy.TERMINAL_PRIMARY_FIELD,policy.FRONT_FIELD):
        old=admitted[key];admitted[key]="unknown"
        with pytest.raises(ValueError,match="policy"):fixtures._build(current)
        admitted[key]=old


def test_intrinsic_and_ordinary_deep_reopen_the_same_terminal_policy_bytes(tmp_path,monkeypatch):
    from qcsd_lab import capture_session,verification
    from qcsd_lab.util import sha256_file
    runner=tmp_path/"samples"/"sample"/"neqo";runner.mkdir(parents=True)
    native,*_=partial_fixture(runner)
    source={"preparation":{**preparation(),policy.TERMINAL_PRIMARY_FIELD:policy.TERMINAL_PRIMARY_POLICY}}
    prepared=tmp_path/"workload.json";prepared.write_text(json.dumps(source))
    real=policy.validate_terminal_primary_source_binding
    calls=[]
    class Reopened(Exception):pass
    def reopen(manifest,run,**kwargs):
        real(manifest,run,**kwargs)
        calls.append(kwargs["runner_directory"]);raise Reopened
    monkeypatch.setattr(policy,"validate_terminal_primary_source_binding",reopen)
    with pytest.raises(Reopened):
        capture_session._validate_run_binding(native,manifest=prepared,application_workload_source=prepared,
            workload_id="fixture",defense=SimpleNamespace(kind="tamaraw"),seed=0,
            context=SimpleNamespace(),runner_directory=runner)
    experiment={"configuration":{"workloads":[{"id":"fixture","manifest":"workload.json","sha256":sha256_file(prepared)}]},
        "samples":[{"state":"accepted","workload_id":"fixture","path":"samples/sample"}]}
    with pytest.raises(Reopened):verification._validate_policy_application_responses(tmp_path,experiment)
    assert calls==[runner,runner]


def test_v12_actual_prepare_terminal_reopens_three_raw_replays_and_all_graph_resources(context, tmp_path, monkeypatch):
    current = _amended_context(context, tmp_path, revision=12)
    candidate, navigation, h3, screen = _auto_page(current, tmp_path)
    original_seal = prepare.write_frozen_manifest
    sealed = []
    def seal(path, manifest, **kwargs):
        assert not path.exists() and manifest["preparation"][policy.FRONT_FIELD] == policy.FRONT_POLICY
        sealed.append(deepcopy(manifest)); return original_seal(path, manifest, **kwargs)
    monkeypatch.setattr(prepare, "write_frozen_manifest", seal)
    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {origin: "1.1.1.1" for origin in origins}
            result.origin_ip_pins[url.rstrip("/")] = "8.8.8.8"
            return result
        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs[policy.TERMINAL_PRIMARY_FIELD] == policy.TERMINAL_PRIMARY_POLICY and kwargs[policy.FRONT_FIELD] == policy.FRONT_POLICY and kwargs[policy.TAMARAW_FIELD] == policy.TAMARAW_POLICY and kwargs[policy.FIELD] == policy.ACK_START_POLICY
            _, prepared, _ = _prepared_variable_workload(context, tmp_path, monkeypatch, amended=current,
                source_url=url, workload_id=workload_id, output_root=output_root, identity_chaff_headers=True,
                preparation_policies={key: kwargs[key] for key in ("qualified_chaff_origin_policy", policy.FIELD, policy.TAMARAW_FIELD, policy.FRONT_FIELD, policy.TERMINAL_PRIMARY_FIELD)})
            manifest = admission._load(prepared.path.read_bytes()); primary = manifest["preparation"]["expected_responses"][0]
            return SimpleNamespace(prepared=prepared, final_url=url, status=primary["status"], content_type="text/html",
                body_bytes=primary["bytes"], body_sha256=primary["body_sha256"], chromium_version=manifest["preparation"]["chromium_version"])
    receipt = admission.prepare_site(current, candidate_id=candidate["candidate_id"], navigation=navigation, page_h3=h3,
        automated_screen=screen, backend=ProducingBackend(current))
    facts, _, _ = admission._preparation_facts(receipt, current, candidate["candidate_id"])
    assert facts[policy.FRONT_FIELD] == policy.FRONT_POLICY and facts[policy.TAMARAW_FIELD] == policy.TAMARAW_POLICY and len(sealed) == 1
    raw = admission._unpack(receipt.read_bytes(), admission.PREPARATION_TYPE)
    workload = admission._child(current.root, raw["prepared_workload"])
    manifest = admission._load(workload.read_bytes())
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2]
    terminal = admission.produce_site_terminal(current, candidate_id=candidate["candidate_id"], root_surveys=_root_logs(current, tmp_path),
        preparation=receipt, automated_screen=screen)
    reopened = admission.verify_site_terminal(terminal, current)
    assert reopened["outcome"] == "admitted" and reopened["admission"][policy.FRONT_FIELD] == policy.FRONT_POLICY
    assert admission.acquisition_status(current)["formal_accepted_trace_count"] == 0
    assert manifest["preparation"][policy.TERMINAL_PRIMARY_FIELD] == policy.TERMINAL_PRIMARY_POLICY
    assert reopened["admission"][policy.TERMINAL_PRIMARY_FIELD] == policy.TERMINAL_PRIMARY_POLICY
    manifest["preparation"].pop(policy.TERMINAL_PRIMARY_FIELD)
    workload.write_bytes(admission._json(manifest))
    with pytest.raises(ValueError, match="terminal primary"):
        admission.verify_prepared_workload(workload, admission._child(current.root, raw["full_resource_graph"]), current,
            selected_page_url=f"https://{candidate['domain']}/")
