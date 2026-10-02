from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_page_evidence as page
from qcsd_lab import rapid_site_admission as admission
from qcsd_lab import rapid_study_profile as profile
from qcsd_lab.class_acquisition import ExistingAcquisitionBackend, NavigationDiscovery
from qcsd_lab.discover import DiscoveryResult
from qcsd_lab.prepare import PreparedWorkload
from tools import h3_curated_survey as curated
from tools import h3_rapid_fallback_survey as fallback
from tools import rapid_acquire
from tests.test_class_acquisition import _prepared_manifest

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
SOURCE = ROOT / "config/curated-sources/crux-73-v1.raw.json"
SOURCE_RECEIPT = ROOT / "config/curated-sources/crux-73-v1.source.json"
CATALOGUE = ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"


def _probe(url: str) -> dict:
    raw = json.dumps({"resources": [{
        "id": 0, "url": url, "type": "Unknown", "content_length": 42,
        "data_length": 42, "chaff_priority": False, "known_valid": True,
        "depends_on": [], "headers": [],
    }]})
    return {"url": url, "started_at": datetime.now(UTC).isoformat(),
            "completed_at": datetime.now(UTC).isoformat(), "resolver_addresses": ["8.8.8.8"],
            "resolver_error": None, "exit_code": 0, "stdout_sha256": admission._sha(b""),
            "stdout_excerpt": "", "output_sha256": admission._sha(raw.encode()),
            "output_text": raw, "known_valid": True, "outcome": "known-valid"}


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> admission.AdmissionContext:
    runtime = {
        "image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False,
        "lab_patch_sha256": admission._sha(b""), "neqo_commit": "2" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": admission._sha(b""), "neqo_pinned_commit": "2" * 40,
    }
    manifest = tmp_path / "source.json"
    manifest.write_bytes(admission._json(runtime))
    client = tmp_path / "client"
    client.write_bytes(b"immutable test executable")
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(manifest))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "d" * 64)
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(client))
    nav_sources = {name: Path(__import__(name, fromlist=["__file__"]).__file__)
                   for name in page.implementation_hashes("navigation")}
    page_sources = {**nav_sources, "qcsd_lab.h3_prebaseline": ROOT / "src/qcsd_lab/h3_prebaseline.py",
                    "neqo-qcsd-client": client}
    return admission.initialize_acquisition(
        tmp_path / "acquisition", profile_path=PROFILE, source=SOURCE, source_receipt=SOURCE_RECEIPT,
        catalogue=CATALOGUE, source_manifest=manifest, admission_image_digest="sha256:" + "d" * 64,
        not_before_utc=datetime.now(UTC) - timedelta(seconds=1),
        module_sources={
            "curated": {"tools.h3_curated_survey": Path(curated.__file__),
                        "qcsd_lab.h3_prebaseline": ROOT / "src/qcsd_lab/h3_prebaseline.py",
                        "qcsd_lab.rapid_study_profile": Path(profile.__file__)},
            "fallback": {"tools.h3_rapid_fallback_survey": Path(fallback.__file__),
                         "qcsd_lab.h3_prebaseline": ROOT / "src/qcsd_lab/h3_prebaseline.py",
                         "qcsd_lab.rapid_study_profile": Path(profile.__file__)},
            "navigation": nav_sources, "page": page_sources,
            "preparation": admission.preparation_implementation_sources(),
        },
    )


def _page_files(context: admission.AdmissionContext, tmp_path: Path, candidate=None) -> tuple[dict, Path, Path, Path]:
    candidate = candidate or context.candidates[0]
    domain = candidate["domain"]
    navigation = tmp_path / f"{candidate['candidate_id']}-navigation.json"
    backend = ExistingAcquisitionBackend(navigation=lambda _: NavigationDiscovery(
        domain, (), (f"https://{domain}",), (), ((f"https://{domain}/", (f"https://{domain}",)),),
    ))
    page.produce_navigation_receipt(output=navigation, profile=PROFILE, source=SOURCE, catalogue=CATALOGUE,
                                    candidate_id=candidate["candidate_id"], execution_binding=context.execution_binding,
                                    backend=backend)
    h3 = tmp_path / f"{candidate['candidate_id']}-h3.json"
    page.produce_selected_page_h3_receipt(
        output=h3, navigation_receipt=navigation, selected_page_ordinal=0, profile=PROFILE, source=SOURCE,
        catalogue=CATALOGUE, candidate_id=candidate["candidate_id"], execution_binding=context.execution_binding,
        expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
        not_before_utc=context.not_before_utc, probe=_probe,
    )
    review = tmp_path / f"{candidate['candidate_id']}-review.json"
    admission.produce_human_review(review, context, candidate_id=candidate["candidate_id"],
                                  reviewed_url=f"https://{domain}/", reviewer="Named human", decision="approved-public-page",
                                  reason=None, human_confirmed=True)
    return candidate, navigation, h3, review


class Backend:
    def __init__(self, context, *, cross_origin=True, error=False):
        self.context, self.cross_origin, self.error = context, cross_origin, error
        self.calls = []

    def discover(self, url, approved):
        self.calls.append(("discover", tuple(approved)))
        origins = sorted({url.rstrip("/"), *( ["https://cdn.example"] if self.cross_origin else [])})
        return DiscoveryResult(url, url, "test-chromium", 10_000, len(origins), origins, origins,
                               [], [], {value: "1.1.1.1" for value in origins}, origins)

    def prepare(self, workload_id, url, approved, output_root, *, origin_ip_pins):
        self.calls.append(("prepare", tuple(approved), origin_ip_pins))
        if self.error:
            raise RuntimeError("retained live preparation failure")
        manifest = _prepared_manifest(url, approved, source_override=dict(self.context.expected_runtime_source))
        output_root.mkdir()
        path = output_root / f"{workload_id}.json"
        raw = admission._json(manifest)
        path.write_bytes(raw)
        return SimpleNamespace(prepared=PreparedWorkload(path, admission._sha(raw), len(manifest["resources"]), len(approved)),
                               final_url=url, status=200, content_type="text/html", body_bytes=100,
                               body_sha256=f"{1:064x}", chromium_version="test-chromium")


def _root_logs(context, tmp_path, *, dns_missing=False, response_invalid=False):
    logs = []
    first_domain = context.candidates[0]["domain"]
    def probe(url):
        if dns_missing and url == f"https://{first_domain}/":
            return {**_probe(url), "resolver_addresses": [], "resolver_error": "gaierror: [Errno -2] Name or service not known",
                    "exit_code": None, "stdout_sha256": admission._sha(b""), "stdout_excerpt": "",
                    "output_sha256": None, "output_text": None, "known_valid": None, "outcome": "ambiguous"}
        if response_invalid and url == f"https://{first_domain}/":
            value = _probe(url)
            output = json.loads(value["output_text"])
            output["resources"][0]["known_valid"] = False
            raw = json.dumps(output)
            return {**value, "output_sha256": admission._sha(raw.encode()), "output_text": raw,
                    "known_valid": False, "outcome": "ambiguous"}
        return _probe(url)
    for start, count in ((0, 30), (30, 30), (60, 13)):
        path = tmp_path / f"roots-{start:03d}.jsonl"
        curated.run_survey(source=SOURCE, receipt=SOURCE_RECEIPT, output=path, start_index=start,
                           count=count, study_version=5, profile=PROFILE, catalogue=CATALOGUE, probe=probe)
        logs.append(path)
    return logs


def _prepare(context, tmp_path, *, cross_origin=True, error=False, candidate=None):
    candidate, navigation, h3, review = _page_files(context, tmp_path, candidate)
    backend = Backend(context, cross_origin=cross_origin, error=error)
    path = admission.prepare_site(context, candidate_id=candidate["candidate_id"], navigation=navigation,
                                  page_h3=h3, human_review=review, backend=backend)
    return candidate, review, path, backend


def test_init_reopens_frozen_independent_inputs_and_zero_credit(context):
    loaded = admission.load_admission_context(context.root)
    assert loaded.execution_binding == context.execution_binding
    status = admission.acquisition_status(loaded)
    assert status["formal_trace_target"] == 16000
    assert status["formal_accepted_trace_count"] == status["admitted_site_count"] == 0
    assert status["next_candidate"] == loaded.candidates[0]


def test_human_review_cannot_be_inferred_or_reused_for_another_page(context, tmp_path):
    candidate = context.candidates[0]
    url = f"https://{candidate['domain']}/"
    output = tmp_path / "review.json"
    with pytest.raises(ValueError, match="explicitly confirm"):
        admission.produce_human_review(output, context, candidate_id=candidate["candidate_id"], reviewed_url=url,
                                      reviewer="Human", decision="approved-public-page", reason=None, human_confirmed=False)
    admission.produce_human_review(output, context, candidate_id=candidate["candidate_id"], reviewed_url=url,
                                  reviewer="Human", decision="approved-public-page", reason=None, human_confirmed=True)
    with pytest.raises(ValueError, match="exact page"):
        admission.verify_human_review(output, context, candidate_id=candidate["candidate_id"], reviewed_url=url + "another")
    with pytest.raises(FileExistsError):
        admission.produce_human_review(output, context, candidate_id=candidate["candidate_id"], reviewed_url=url,
                                      reviewer="Human", decision="approved-public-page", reason=None, human_confirmed=True)


def test_full_live_path_reopens_every_root_page_review_and_complete_graph(context, tmp_path):
    candidate, review, preparation, backend = _prepare(context, tmp_path)
    roots = _root_logs(context, tmp_path)
    path = admission.produce_site_terminal(context, candidate_id=candidate["candidate_id"], root_surveys=roots,
                                          human_review=review, reviewed_url=f"https://{candidate['domain']}/",
                                          preparation=preparation)
    facts = admission.verify_site_terminal(path, context)
    assert facts["outcome"] == "admitted"
    assert facts["admission"]["cross_origin_resource_count"] == 1
    assert len(backend.calls) == 3
    assert admission.acquisition_status(context)["admitted_site_count"] == 1
    assert admission.acquisition_status(context)["formal_accepted_trace_count"] == 0


def test_single_origin_is_ineligible_only_after_valid_full_graph(context, tmp_path):
    candidate, review, preparation, _ = _prepare(context, tmp_path, cross_origin=False)
    path = admission.produce_site_terminal(context, candidate_id=candidate["candidate_id"], root_surveys=_root_logs(context, tmp_path),
                                          human_review=review, reviewed_url=f"https://{candidate['domain']}/", preparation=preparation)
    facts = admission.verify_site_terminal(path, context)
    assert facts["outcome"] == "ineligible" and facts["admission"] is None
    assert facts["selected_page_h3_proof"]["outcome"] == "known-valid"


def test_preparation_failure_retained_retryable_without_terminal_or_advance(context, tmp_path):
    candidate, navigation, h3, review = _page_files(context, tmp_path)
    with pytest.raises(RuntimeError, match="retained live"):
        admission.prepare_site(context, candidate_id=candidate["candidate_id"], navigation=navigation,
                               page_h3=h3, human_review=review, backend=Backend(context, error=True))
    status = admission.acquisition_status(context)
    assert status["next_candidate"] == candidate
    assert status["terminal_count"] == status["admitted_site_count"] == 0
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    successor = admission.prepare_site(context, candidate_id=candidate["candidate_id"], navigation=navigation,
                                       page_h3=h3, human_review=review, backend=Backend(context))
    assert successor.parent.name == "attempt-000002"


def test_dns_deferral_is_explicit_operational_zero_credit_and_never_ineligible(context, tmp_path):
    candidate = context.candidates[0]
    path = admission.produce_site_terminal(context, candidate_id=candidate["candidate_id"],
                                          root_surveys=_root_logs(context, tmp_path, dns_missing=True), defer_root=True)
    facts = admission.verify_site_terminal(path, context)
    assert facts["outcome"] == "screen-deferred" and facts["admission"] is None
    assert facts["triage"]["reason"] == "operational-dns-name-not-found"
    status = admission.acquisition_status(context)
    assert status["terminal_count"] == 1 and status["admitted_site_count"] == 0
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "zero-credit-operational-dns-screen-deferred"


def test_prepared_graph_cannot_be_shrunk_or_source_identity_substituted(context, tmp_path):
    candidate, _, prepared, _ = _prepare(context, tmp_path)
    payload = admission._unpack(prepared.read_bytes(), admission.PREPARATION_TYPE)
    workload = admission._child(context.root, payload["prepared_workload"])
    graph = admission._child(context.root, payload["full_resource_graph"])
    value = json.loads(graph.read_bytes())
    value["resources"].pop()
    graph.write_bytes(admission._json(value))
    with pytest.raises(ValueError, match="complete resource graph"):
        admission.verify_prepared_workload(workload, graph, context, selected_page_url=f"https://{candidate['domain']}/")
    with pytest.raises(ValueError, match="bytes changed"):
        admission.acquisition_status(context)


def test_root_survey_is_reopened_with_independent_hashes_and_controls(context, tmp_path):
    logs = _root_logs(context, tmp_path)
    refs = [admission.import_evidence(context.root, path) for path in logs]
    decision = admission.verify_root_screen(context, context.candidates[0]["candidate_id"], refs)
    assert decision["root_screen"]["controls_passed"] is True
    bad_context = replace(context, mounted_module_hashes={**context.mounted_module_hashes,
                          "curated": {**context.mounted_module_hashes["curated"], "tools.h3_curated_survey": "0" * 64}})
    with pytest.raises(ValueError, match="source, image or protocol binding"):
        admission.verify_root_screen(bad_context, context.candidates[0]["candidate_id"], refs)


def test_driver_cannot_skip_unresolved_candidate_and_cohort_cannot_fabricate_ten(context):
    with pytest.raises(ValueError, match="cannot skip"):
        rapid_acquire._next_candidate(context, context.candidates[1]["candidate_id"])
    with pytest.raises(ValueError, match="cohort is incomplete"):
        admission.build_acquisition_cohort(context, "launch-10")
    assert not (context.root / "cohorts").exists()


def test_checkpoint_chain_preserves_old_attempt_bytes(context, tmp_path):
    candidate, navigation, h3, review = _page_files(context, tmp_path)
    with pytest.raises(RuntimeError):
        admission.prepare_site(context, candidate_id=candidate["candidate_id"], navigation=navigation,
                               page_h3=h3, human_review=review, backend=Backend(context, error=True))
    intent = next((context.root / "attempts").rglob("intent.json"))
    value = json.loads(intent.read_bytes())
    value["started_at"] = "2026-01-01T00:00:00Z"
    intent.write_bytes(admission._json(value))
    with pytest.raises(ValueError, match="bytes changed"):
        admission.write_checkpoint(context)


@pytest.fixture
def checkpoint_context(tmp_path, monkeypatch):
    root = tmp_path / "checkpoint-acquisition"
    root.mkdir()
    context = SimpleNamespace(root=root, provenance_sha256="a" * 64)
    monkeypatch.setattr(admission, "acquisition_status", lambda _: {
        "provenance_sha256": context.provenance_sha256, "attempts": {},
    })
    return context


def _historical_checkpoints(context, inventories):
    directory = context.root / "checkpoints"
    directory.mkdir()
    previous, paths = None, []
    for sequence, inventory in enumerate(inventories, start=1):
        payload = {
            "sequence": sequence, "previous_sha256": previous, "recorded_at": admission._now(),
            "status": {"provenance_sha256": context.provenance_sha256,
                       "attempts": {"fixture": [{"inventory": inventory}]}},
        }
        path = directory / f"checkpoint-{sequence:06d}.json"
        raw = admission._json(admission._bind(admission.CHECKPOINT_TYPE, payload))
        path.write_bytes(raw)
        previous = admission._sha(raw)
        paths.append(path)
    return paths


def test_checkpoint_reopens_each_unique_reference_once_per_invocation(checkpoint_context, monkeypatch):
    evidence = checkpoint_context.root / "evidence.bin"
    evidence.write_bytes(b"retained evidence")
    reference = admission.evidence_reference(checkpoint_context.root, evidence)
    paths = _historical_checkpoints(checkpoint_context, [[reference] * 3, [reference] * 2, [reference]])
    original_read, counts = admission._read, {}

    def counted_read(path):
        path = Path(path)
        counts[path] = counts.get(path, 0) + 1
        return original_read(path)

    monkeypatch.setattr(admission, "_read", counted_read)
    output = admission.write_checkpoint(checkpoint_context)
    assert counts[evidence] == 1
    assert all(counts[path] == 1 for path in paths)
    payload = admission._unpack(original_read(output), admission.CHECKPOINT_TYPE)
    assert payload["sequence"] == 4
    assert payload["previous_sha256"] == admission._sha(original_read(paths[-1]))
    counts.clear()
    admission.write_checkpoint(checkpoint_context)
    assert counts[evidence] == 1


def test_checkpoint_dedup_still_reopens_changed_bytes_on_next_invocation(checkpoint_context):
    evidence = checkpoint_context.root / "evidence.bin"
    evidence.write_bytes(b"original bytes")
    reference = admission.evidence_reference(checkpoint_context.root, evidence)
    _historical_checkpoints(checkpoint_context, [[reference], [reference]])
    admission.write_checkpoint(checkpoint_context)
    evidence.write_bytes(b"changed bytes")
    with pytest.raises(ValueError, match="bytes changed"):
        admission.write_checkpoint(checkpoint_context)
    assert not (checkpoint_context.root / "checkpoints/checkpoint-000004.json").exists()


def test_checkpoint_rejects_conflicting_historical_hashes(checkpoint_context):
    evidence = checkpoint_context.root / "evidence.bin"
    evidence.write_bytes(b"retained evidence")
    reference = admission.evidence_reference(checkpoint_context.root, evidence)
    _historical_checkpoints(checkpoint_context, [[reference], [{**reference, "sha256": "b" * 64}]])
    with pytest.raises(ValueError, match="conflicting evidence hashes"):
        admission.write_checkpoint(checkpoint_context)
    assert not (checkpoint_context.root / "checkpoints/checkpoint-000003.json").exists()


@pytest.mark.parametrize("mutation", ["extra-field", "missing-hash", "non-string-hash", "non-string-path"])
def test_checkpoint_dedup_rejects_malformed_repeated_references(checkpoint_context, mutation):
    evidence = checkpoint_context.root / "evidence.bin"
    evidence.write_bytes(b"retained evidence")
    reference = admission.evidence_reference(checkpoint_context.root, evidence)
    malformed = dict(reference)
    if mutation == "extra-field":
        malformed["extra"] = True
    elif mutation == "missing-hash":
        del malformed["sha256"]
    elif mutation == "non-string-hash":
        malformed["sha256"] = None
    else:
        malformed["path"] = [reference["path"]]
    _historical_checkpoints(checkpoint_context, [[reference], [malformed, malformed]])
    with pytest.raises(ValueError, match="reference is (malformed|unsafe)"):
        admission.write_checkpoint(checkpoint_context)


@pytest.mark.parametrize("kind", ["escape", "absolute", "symlink"])
def test_checkpoint_rejects_unsafe_references_even_when_repeated(checkpoint_context, kind):
    evidence = checkpoint_context.root / "evidence.bin"
    evidence.write_bytes(b"retained evidence")
    if kind == "escape":
        name = "../evidence.bin"
    elif kind == "absolute":
        name = str(evidence)
    else:
        (checkpoint_context.root / "linked.bin").symlink_to(evidence)
        name = "linked.bin"
    reference = {"path": name, "sha256": admission._sha(evidence.read_bytes())}
    _historical_checkpoints(checkpoint_context, [[reference, reference]])
    with pytest.raises(ValueError, match="(reference is unsafe|contains a symlink)"):
        admission.write_checkpoint(checkpoint_context)


@pytest.mark.parametrize("mutation", ["gap", "sequence", "predecessor", "provenance", "envelope"])
def test_checkpoint_dedup_preserves_chain_validation(checkpoint_context, mutation):
    path = _historical_checkpoints(checkpoint_context, [[]])[0]
    receipt = json.loads(path.read_bytes())
    if mutation == "gap":
        path.rename(path.with_name("checkpoint-000002.json"))
    else:
        if mutation == "sequence":
            receipt["payload"]["sequence"] = 2
        elif mutation == "predecessor":
            receipt["payload"]["previous_sha256"] = "b" * 64
        elif mutation == "provenance":
            receipt["payload"]["status"]["provenance_sha256"] = "b" * 64
        if mutation == "envelope":
            receipt["payload_sha256"] = "b" * 64
        else:
            receipt = admission._bind(admission.CHECKPOINT_TYPE, receipt["payload"])
        path.write_bytes(admission._json(receipt))
    with pytest.raises(ValueError, match="(checkpoint chain|invalid .*checkpoint receipt)"):
        admission.write_checkpoint(checkpoint_context)


def test_cli_help_exposes_actual_navigation_probe_prepare_and_seal(capsys):
    with pytest.raises(SystemExit) as exit_info:
        rapid_acquire.main(["--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "navigate" in output and "probe-page" in output and "prepare" in output and "seal" in output


def _amended_context(context, tmp_path, *, revision=1):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    from qcsd_lab.rapid_selection_amendment import build_selection_amendment
    amendment = tmp_path / "selection-amendment.json"
    amendment.write_bytes(admission._json(build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=revision,
    )))
    provenance = admission._unpack(admission._read(context.root / "provenance.json"), admission.PROVENANCE_TYPE)
    paths = {key: admission._child(context.root, ref) for key, ref in provenance["inputs"].items()}
    modules = {group: {name: admission._child(context.root, ref) for name, ref in sources.items()}
               for group, sources in provenance["module_sources"].items()}
    if revision >= 3:
        from qcsd_lab import rapid_collector_failure_evidence as collector
        modules[admission.COLLECTOR_GROUP] = collector.implementation_sources()
    if revision >= 4:
        from qcsd_lab import rapid_attempt_failure_evidence as observer
        modules[admission.ATTEMPT_GROUP] = observer.implementation_sources(application_response_policy=revision == 5)
    if revision == 5:
        modules["preparation"] = admission.preparation_implementation_sources(application_response_policy=True)
    return admission.initialize_acquisition(
        tmp_path / "amended-acquisition", profile_path=paths["profile"], source=paths["source"],
        source_receipt=paths["source_receipt"], catalogue=paths["catalogue"],
        source_manifest=paths["source_manifest"], admission_image_digest=context.execution_binding["admission_image_digest"],
        not_before_utc=context.not_before_utc,
        module_sources={**modules, admission.BROWSER_POLICY_GROUP: browser.implementation_sources()},
        selection_amendment=amendment,
    )


def _typed_egress_failure():
    from qcsd_lab.browser_egress import NonReplayableEgressGuard
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    guard.record(api="WebSocket", mechanism="playwright-websocket-route", url="wss://onweeralarm.nl/weather")
    try:
        guard.raise_if_failed()
    except Exception as error:
        return error
    raise AssertionError("guard did not produce its typed failure")


def _policy_observation(context, tmp_path, *, error=None):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    candidate = context.candidates[0]
    def navigate(_):
        raise error if error is not None else _typed_egress_failure()
    output = tmp_path / "fresh-policy-observation.json"
    browser.produce_navigation_policy_observation(
        output=output, profile=PROFILE, source=SOURCE, catalogue=CATALOGUE,
        candidate_id=candidate["candidate_id"], execution_binding=context.execution_binding,
        policy_amendment_sha256=context.selection_amendment_sha256,
        expected_implementation_hashes=context.mounted_module_hashes[admission.BROWSER_POLICY_GROUP],
        not_before_utc=context.browser_policy_not_before_utc,
        backend=ExistingAcquisitionBackend(navigation=navigate),
    )
    return output


def test_amendment_preserves_original_context_and_reopens_unchanged_root_observations(context, tmp_path):
    roots = _root_logs(context, tmp_path)
    original_provenance = admission._read(context.root / "provenance.json")
    amended = _amended_context(context, tmp_path)
    assert amended.not_before_utc == context.not_before_utc
    assert amended.browser_policy_not_before_utc > context.not_before_utc
    assert amended.selection_amendment_sha256 == admission._sha(amended.selection_amendment_bytes)
    refs = [admission.import_evidence(amended.root, path) for path in roots]
    facts = admission.verify_root_screen(amended, amended.candidates[0]["candidate_id"], refs)
    assert facts["root_screen"]["outcome"] == "known-valid"
    assert admission._read(context.root / "provenance.json") == original_provenance
    assert admission.load_admission_context(context.root).selection_amendment_bytes is None
    assert admission.acquisition_status(amended)["formal_trace_target"] == 16000


def test_browser_policy_failure_requires_explicit_seal_and_has_zero_credit(context, tmp_path, monkeypatch):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path)
    def fail(_):
        raise _typed_egress_failure()
    monkeypatch.setattr(browser, "ExistingAcquisitionBackend", lambda: ExistingAcquisitionBackend(navigation=fail))
    candidate = amended.candidates[0]
    output = rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    before = admission.acquisition_status(amended)
    assert before["next_candidate"] == candidate
    assert before["terminal_count"] == 0
    assert before["attempts"][candidate["candidate_id"]][0]["state"] == "browser-policy-failure-needs-explicit-terminal"
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"], root_surveys=roots,
                                               browser_policy_failure=output)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "screen-deferred" and facts["admission"] is None
    assert facts["selected_page_h3_proof"] is None and facts["site_safety_review"] is None
    assert facts["browser_policy_failure"]["raw_failure"]["evidence"]["non_replayable_egress"]["by_api"] == {"WebSocket": 1}
    after = admission.acquisition_status(amended)
    assert after["next_candidate"] == amended.candidates[1]
    assert after["admitted_site_count"] == after["formal_accepted_trace_count"] == 0
    assert after["attempts"][candidate["candidate_id"]][-1]["state"] == "zero-credit-browser-policy-screen-deferred"
    payload = admission._unpack(terminal.read_bytes(), admission.TERMINAL_TYPE)
    payload["completed_at"] = (amended.browser_policy_not_before_utc - timedelta(milliseconds=1)).isoformat()
    terminal.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE, payload)))
    with pytest.raises(ValueError, match="predates its proof"):
        admission.verify_site_terminal(terminal, amended)


def test_baseline_cannot_promote_browser_policy_failure_to_terminal(context, tmp_path):
    amended = _amended_context(context, tmp_path)
    proof = _policy_observation(amended, tmp_path)
    with pytest.raises(ValueError, match="prospective selection amendment"):
        admission.produce_site_terminal(context, candidate_id=context.candidates[0]["candidate_id"],
                                        browser_policy_failure=proof)
    assert admission.acquisition_status(context)["terminal_count"] == 0


def test_browser_policy_proof_is_fresh_and_reopened_after_cached_verification(context, tmp_path):
    amended = _amended_context(context, tmp_path)
    proof = _policy_observation(amended, tmp_path)
    candidate = amended.candidates[0]
    admission.browser_policy_failure_facts(proof, amended, candidate["candidate_id"])
    value = admission._load(proof.read_bytes())
    value["payload"]["started_at"] = (amended.browser_policy_not_before_utc - timedelta(seconds=1)).isoformat()
    proof.write_bytes(admission._json(admission._bind(value["receipt_type"], value["payload"])))
    with pytest.raises(ValueError, match="stale or unordered"):
        admission.browser_policy_failure_facts(proof, amended, candidate["candidate_id"])


@pytest.mark.parametrize("error", [RuntimeError("runtime infrastructure failure"), TimeoutError("browser timeout")])
def test_amended_navigation_keeps_unexpected_failures_retryable(context, tmp_path, monkeypatch, error):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    amended = _amended_context(context, tmp_path)
    def fail(_):
        raise error
    monkeypatch.setattr(browser, "ExistingAcquisitionBackend", lambda: ExistingAcquisitionBackend(navigation=fail))
    candidate = amended.candidates[0]
    with pytest.raises(type(error)):
        rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    status = admission.acquisition_status(amended)
    assert status["next_candidate"] == candidate and status["terminal_count"] == 0
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    assert not any(amended.root.rglob("navigation-observation.json"))


def test_amended_deferral_leaves_ordinary_full_graph_admission_and_cohort_count_intact(context, tmp_path):
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path)
    proof = _policy_observation(amended, tmp_path)
    admission.produce_site_terminal(amended, candidate_id=amended.candidates[0]["candidate_id"],
                                    root_surveys=roots, browser_policy_failure=proof)
    candidate, review, preparation, _ = _prepare(amended, tmp_path, candidate=amended.candidates[1])
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"], root_surveys=roots,
                                               human_review=review, reviewed_url=f"https://{candidate['domain']}/",
                                               preparation=preparation)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "admitted" and facts["admission"]["cross_origin_resource_count"] == 1
    assert admission.acquisition_status(amended)["admitted_site_count"] == 1
    with pytest.raises(ValueError, match="incomplete"):
        admission.build_acquisition_cohort(amended, "launch-10")


def test_selection_amendment_requires_exact_canonical_receipt_bytes():
    from qcsd_lab.rapid_selection_amendment import build_selection_amendment
    receipt = build_selection_amendment(published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    canonical = admission._json(receipt)
    assert admission._selection_amendment_payload(canonical)["parent_profile_sha256"] == profile.FROZEN_V5_PROFILE_SHA256
    with pytest.raises(ValueError, match="canonical immutable bytes"):
        admission._selection_amendment_payload(json.dumps(receipt).encode())


def test_successful_amended_cohort_uses_its_registered_create_only_writer(context, tmp_path, monkeypatch):
    from tests.test_rapid_selection_amendment import _terminal
    from qcsd_lab.rapid_selection_amendment import AMENDED_COHORT_RECEIPT_TYPE
    amended = _amended_context(context, tmp_path)
    references, admitted = [], 0
    directory = amended.root / "fixture-cohort-decisions"
    directory.mkdir()
    for candidate in amended.candidates:
        facts = _terminal(candidate, dict(amended.execution_binding))
        path = directory / f"{candidate['candidate_id']}.json"
        path.write_bytes(admission._json(facts))
        references.append(admission.evidence_reference(amended.root, path))
        admitted += facts["outcome"] == "admitted"
        if admitted == 10:
            break
    # Other tests independently exercise the full graph terminal verifier. This
    # boundary uses valid cohort facts to verify publication and its own schema.
    monkeypatch.setattr(admission, "acquisition_status", lambda _: {"attempts": {}, "terminal_prefix": references})
    monkeypatch.setattr(admission, "verify_site_terminal", lambda path, _: admission._load(admission._read(path)))
    monkeypatch.setattr(admission, "write_checkpoint", lambda _: None)
    output = admission.build_acquisition_cohort(amended, "launch-10")
    receipt = admission._load(output.read_bytes())
    assert receipt["receipt_type"] == AMENDED_COHORT_RECEIPT_TYPE
    assert receipt["payload"]["selection_amendment_sha256"] == amended.selection_amendment_sha256
    assert len(receipt["payload"]["selected_candidate_ids"]) == 10
    with pytest.raises(FileExistsError):
        admission.build_acquisition_cohort(amended, "launch-10")


def _auto_page(context, tmp_path, *, prior=None):
    candidate, navigation, h3, _ = prior or _page_files(context, tmp_path)
    screen = tmp_path / "automatic-screen.json"
    admission.produce_automated_site_screen(
        screen, context, candidate_id=candidate["candidate_id"], navigation=navigation,
        page_h3=h3, selected_page_ordinal=0,
    )
    return candidate, navigation, h3, screen


def _render_failure():
    from qcsd_lab.acquisition_errors import PassiveRenderPolicyError
    from tests.test_prepare import _actual_render_failure_evidence
    return PassiveRenderPolicyError("actual typed hard cap", evidence=_actual_render_failure_evidence())


def test_v2_full_graph_admission_reuses_unchanged_page_observations_and_has_distinct_screen(context, tmp_path):
    prior = _page_files(context, tmp_path)
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=2)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path, prior=prior)
    raw_screen = admission._unpack(screen.read_bytes(), admission.AUTOMATED_SCREEN_TYPE)
    assert not {"reviewer", "human_confirmed", "human_review"} & set(raw_screen)
    assert raw_screen["screen_policy"]["content_classification_claimed"] is False
    preparation = admission.prepare_site(
        amended, candidate_id=candidate["candidate_id"], navigation=navigation, page_h3=h3,
        automated_screen=screen, backend=Backend(amended),
    )
    prepared = admission._unpack(preparation.read_bytes(), admission.PREPARATION_TYPE)
    assert set(prepared["inputs"]) == {"navigation", "page_h3", "automated_screen"}
    terminal = admission.produce_site_terminal(
        amended, candidate_id=candidate["candidate_id"], root_surveys=roots,
        automated_screen=screen, preparation=preparation,
    )
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "admitted" and facts["site_safety_review"] is None
    assert facts["automated_site_screen"]["decision"] == "automatic-policy-pass"
    assert facts["admission"]["cross_origin_resource_count"] == 1
    assert facts["admission"]["full_resource_graph_sha256"]
    assert admission.acquisition_status(amended)["formal_trace_target"] == 16000
    with pytest.raises(FileExistsError):
        admission.produce_automated_site_screen(screen, amended, candidate_id=candidate["candidate_id"],
                                               navigation=navigation, page_h3=h3, selected_page_ordinal=0)


def test_v2_automated_screen_is_prospective_and_exact_and_reopened(context, tmp_path):
    candidate, navigation, h3, _ = _page_files(context, tmp_path)
    with pytest.raises(ValueError, match="revision 2"):
        admission.produce_automated_site_screen(tmp_path / "legacy-auto.json", context,
                                               candidate_id=candidate["candidate_id"], navigation=navigation,
                                               page_h3=h3, selected_page_ordinal=0)
    amended = _amended_context(context, tmp_path, revision=2)
    with pytest.raises(ValueError, match="ordinal differs"):
        admission.produce_automated_site_screen(tmp_path / "wrong-ordinal.json", amended,
                                               candidate_id=candidate["candidate_id"], navigation=navigation,
                                               page_h3=h3, selected_page_ordinal=1)
    _, _, _, screen = _auto_page(amended, tmp_path, prior=(candidate, navigation, h3, None))
    original = screen.read_bytes()
    for key, invalid in (
        ("selected_page_ordinal", True),
        ("selected_page_url", f"https://{candidate['domain']}/different"),
        ("screened_at", (amended.page_policy_not_before_utc - timedelta(seconds=1)).isoformat()),
        ("implementation_hashes", {key: "0" * 64 for key in amended.mounted_module_hashes["preparation"]}),
    ):
        value = admission._unpack(original, admission.AUTOMATED_SCREEN_TYPE)
        value[key] = invalid
        screen.write_bytes(admission._json(admission._bind(admission.AUTOMATED_SCREEN_TYPE, value)))
        with pytest.raises(ValueError):
            admission.verify_automated_site_screen(screen, amended, candidate_id=candidate["candidate_id"])
    screen.write_bytes(original)
    assert admission.verify_automated_site_screen(screen, amended, candidate_id=candidate["candidate_id"])["scientific_credit"] is False


def test_v2_navigation_render_failure_is_reopened_and_explicitly_zero_credit(context, tmp_path, monkeypatch):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=2)
    def fail(_):
        raise _render_failure()
    monkeypatch.setattr(browser, "ExistingAcquisitionBackend", lambda: ExistingAcquisitionBackend(navigation=fail))
    candidate = amended.candidates[0]
    proof = rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    assert proof.name == "page-policy-failure.json"
    failure = admission.page_policy_failure_facts(proof, amended, candidate["candidate_id"])
    assert failure["action"]["kind"] == "catalogue-boundary-navigation"
    assert failure["failure_page_attribution"] == "unavailable"
    assert failure["raw_failure"]["capture_source"] is None
    assert (proof.parent / "raw-typed-policy-error.json").exists()
    assert admission.acquisition_status(amended)["terminal_count"] == 0
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
                                               root_surveys=roots, page_policy_failure=proof)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "page-policy-screen-deferred" and facts["admission"] is None
    assert facts["automated_site_screen"] is facts["selected_page_h3_proof"] is None
    assert admission.acquisition_status(amended)["admitted_site_count"] == 0
    value = admission._unpack(proof.read_bytes(), admission.PAGE_POLICY_FAILURE_TYPE)
    value["started_at"] = (amended.page_policy_not_before_utc - timedelta(seconds=1)).isoformat()
    proof.write_bytes(admission._json(admission._bind(admission.PAGE_POLICY_FAILURE_TYPE, value)))
    with pytest.raises(ValueError, match="stale or unordered"):
        admission.page_policy_failure_facts(proof, amended, candidate["candidate_id"])


def test_v2_preparation_render_failure_retains_exact_page_and_screen_without_admission(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=2)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class RenderBackend(Backend):
        def discover(self, url, approved):
            raise _render_failure()
    proof = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                    page_h3=h3, automated_screen=screen, backend=RenderBackend(amended))
    assert proof.name == "page-policy-failure.json"
    failure = admission.page_policy_failure_facts(proof, amended, candidate["candidate_id"])
    assert failure["action"]["kind"] == "complete-graph-preparation"
    assert set(failure["implementation_hashes"]) == {"preparation", "browser_policy"}
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
                                               root_surveys=_root_logs(amended, tmp_path),
                                               page_policy_failure=proof, automated_screen=screen)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "page-policy-screen-deferred" and facts["admission"] is None
    assert facts["selected_page_h3_proof"]["url"] == f"https://{candidate['domain']}/"
    assert facts["automated_site_screen"]["receipt_sha256"] == admission._sha(screen.read_bytes())


@pytest.mark.parametrize("error", [RuntimeError("runtime failure"), TimeoutError("timeout")])
def test_v2_preparation_operational_failures_remain_retryable(context, tmp_path, error):
    amended = _amended_context(context, tmp_path, revision=2)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class ErrorBackend(Backend):
        def prepare(self, *args, **kwargs):
            raise error
    with pytest.raises(type(error)):
        admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                page_h3=h3, automated_screen=screen, backend=ErrorBackend(amended))
    status = admission.acquisition_status(amended)
    assert status["next_candidate"] == candidate
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    assert not any(amended.root.rglob("page-policy-failure.json"))


def _actual_collector_failure():
    from qcsd_lab.cdp_targets import CdpTargetIntegrityError, RecursiveCdpTargetRouter
    router = object.__new__(RecursiveCdpTargetRouter)
    router._track_root_srcdoc_lifecycle = True
    router._root_source = object()
    router._root_frame_id = "root-frame"
    try:
        router._handle_root_page_lifecycle("Page.frameDetached", {"frameId": "root-frame", "reason": "remove"})
    except CdpTargetIntegrityError as error:
        return error
    raise AssertionError("actual collector guard failed to reject an invalid root detachment")


@pytest.mark.parametrize("response_invalid", [False, True])
def test_v3_navigation_collector_observation_requires_explicit_cli_seal_and_gives_zero_credit(context, tmp_path, monkeypatch, response_invalid):
    from qcsd_lab import rapid_browser_policy_evidence as browser
    roots = _root_logs(context, tmp_path, response_invalid=response_invalid)
    amended = _amended_context(context, tmp_path, revision=3)
    candidate = amended.candidates[0]
    def fail(_):
        raise _actual_collector_failure()
    monkeypatch.setattr(browser, "ExistingAcquisitionBackend", lambda: ExistingAcquisitionBackend(navigation=fail))
    proof = rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    facts = admission.operational_collector_failure_facts(proof, amended, candidate["candidate_id"])
    assert facts["action"]["kind"] == "catalogue-boundary-navigation"
    assert facts["event_parameters"] == "unavailable-not-reconstructed"
    assert facts["retryable"] is True and facts["whole_domain_ineligible"] is False
    assert facts["actual_attempt_count"] == 1
    assert facts["navigation_receipt_sha256"] is facts["selected_page_h3_receipt_sha256"] is None
    status = admission.acquisition_status(amended)
    assert status["terminal_count"] == 0
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "collector-failure-needs-explicit-terminal"
    args = ["seal", str(amended.root), "--candidate", candidate["candidate_id"], "--collector-failure", str(proof)]
    for root in roots:
        args += ["--root-log", str(root)]
    result = rapid_acquire.run(rapid_acquire._parser().parse_args(args))
    terminal = admission.verify_site_terminal(Path(result["evidence"]), amended)
    assert terminal["outcome"] == "operational-collector-screen-deferred"
    assert terminal["admission"] is terminal["site_safety_review"] is terminal["selected_page_h3_proof"] is None
    assert terminal["automated_site_screen"] is None
    assert terminal["root_screen"]["outcome"] == ("ambiguous" if response_invalid else "known-valid")
    assert result["status"]["next_candidate"] == amended.candidates[1]
    assert result["status"]["admitted_site_count"] == result["status"]["formal_accepted_trace_count"] == 0


def test_v3_prepare_collector_limitation_reopens_exact_supports_without_shrinking_graph(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=3)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class CollectorBackend(Backend):
        def discover(self, url, approved):
            raise _actual_collector_failure()
    proof = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                   page_h3=h3, automated_screen=screen, backend=CollectorBackend(amended))
    assert proof.name == "collector-failure.json"
    failure = admission.operational_collector_failure_facts(proof, amended, candidate["candidate_id"])
    assert failure["action"]["kind"] == "complete-graph-preparation"
    assert failure["selected_page_h3_receipt_sha256"] == admission._sha(h3.read_bytes())
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
                                               root_surveys=_root_logs(amended, tmp_path),
                                               collector_failure=proof, automated_screen=screen)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "operational-collector-screen-deferred" and facts["admission"] is None
    assert facts["selected_page_h3_proof"]["url"] == f"https://{candidate['domain']}/"
    assert facts["automated_site_screen"]["receipt_sha256"] == admission._sha(screen.read_bytes())
    invalid = deepcopy(failure)
    invalid["selected_page_h3_receipt_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="exact page support"):
        admission.validate_operational_collector_failure_facts(
            invalid, candidate=candidate, execution_binding=amended.execution_binding,
            selection_amendment_sha256=amended.selection_amendment_sha256,
            not_before_utc=amended.collector_not_before_utc,
            selected_page_h3_proof=facts["selected_page_h3_proof"], automated_site_screen=facts["automated_site_screen"],
        )


def test_v2_collector_error_remains_unsealed_retryable_and_cannot_accept_v3_flag(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=2)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class CollectorBackend(Backend):
        def discover(self, url, approved):
            raise _actual_collector_failure()
    with pytest.raises(Exception, match="frame detachment identity is invalid"):
        admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                page_h3=h3, automated_screen=screen, backend=CollectorBackend(amended))
    assert not any(amended.root.rglob("collector-failure.json"))
    assert admission.acquisition_status(amended)["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    with pytest.raises(ValueError, match="revision 3"):
        admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"], collector_failure=tmp_path / "fake.json")


@pytest.mark.parametrize("error", [RuntimeError("CdpTargetIntegrityError: simulated"), TimeoutError("transport timeout")])
def test_v3_generic_infrastructure_errors_cannot_gain_collector_deferral(context, tmp_path, error):
    amended = _amended_context(context, tmp_path, revision=3)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class ErrorBackend(Backend):
        def discover(self, *args):
            raise error
    with pytest.raises(type(error)):
        admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                page_h3=h3, automated_screen=screen, backend=ErrorBackend(amended))
    assert not any(amended.root.rglob("collector-failure.json"))
    status = admission.acquisition_status(amended)
    assert status["next_candidate"] == candidate and status["terminal_count"] == 0
    assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"


def test_v3_full_graph_admission_keeps_16000_target_and_original_support_reopening(context, tmp_path):
    prior = _page_files(context, tmp_path)
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=3)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path, prior=prior)
    prepared = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                                      page_h3=h3, automated_screen=screen, backend=Backend(amended))
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
                                               root_surveys=roots, preparation=prepared, automated_screen=screen)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "admitted" and facts["admission"]["cross_origin_resource_count"] == 1
    assert facts["admission"]["full_resource_graph_sha256"]
    assert "operational_collector_failure" not in facts


def test_v4_navigation_actual_failure_requires_seal_and_never_claims_challenge(context, tmp_path, monkeypatch):
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=4)
    def fail(_self, _domain):
        from qcsd_lab.class_acquisition import TerminalProbePolicyError
        raise TerminalProbePolicyError("page-safety-rejected:captcha-or-challenge-widget")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", fail)
    proof = rapid_acquire._page_action(amended, amended.candidates[0]["candidate_id"], SimpleNamespace(command="navigate"))
    assert proof.name == "attempt-failure.json"
    facts = admission.unsuccessful_attempt_failure_facts(proof, amended, amended.candidates[0]["candidate_id"])
    assert facts["failure_scope"] == "unsuccessful-live-backend-attempt"
    assert facts["whole_domain_ineligible"] is False and facts["site_credit"] == 0
    assert "challenge" not in facts["failure_scope"]
    status = admission.acquisition_status(amended)
    assert len(status["terminal_prefix"]) == 0
    assert status["attempts"][amended.candidates[0]["candidate_id"]][0]["state"] == "failed-attempt-needs-explicit-terminal"
    terminal = admission.produce_site_terminal(amended, candidate_id=amended.candidates[0]["candidate_id"],
                                               root_surveys=roots, attempt_failure=proof)
    actual = admission.verify_site_terminal(terminal, amended)
    assert actual["outcome"] == "unsuccessful-live-attempt-screen-deferred" and actual["admission"] is None
    assert admission.acquisition_status(amended)["formal_trace_target"] == 16000
    raw = admission._unpack(proof.read_bytes(), admission.ATTEMPT_FAILURE_TYPE)
    observation = admission._child(amended.root, raw["attempt_observation"])
    retained = admission._load(observation.read_bytes())["payload"]
    path = observation.parent / retained["artifacts"]["traceback"]["path"]
    path.chmod(0o644)
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError):
        admission.verify_site_terminal(terminal, amended)


@pytest.mark.parametrize("mode", ["invalid-return", "internal-source-guard"])
def test_v4_post_call_navigation_or_internal_binding_validation_stays_blocking(context, tmp_path, monkeypatch, mode):
    amended = _amended_context(context, tmp_path, revision=4)
    def invalid(_self, _domain):
        if mode == "invalid-return":
            return "not NavigationDiscovery"
        from qcsd_lab.class_acquisition import TerminalProbePolicyError
        raise TerminalProbePolicyError("prepared workload source/image differs from acquisition runtime")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", invalid)
    with pytest.raises(ValueError):
        rapid_acquire._page_action(amended, amended.candidates[0]["candidate_id"], SimpleNamespace(command="navigate"))
    assert not any(amended.root.rglob("attempt-failure.json"))
    assert admission.acquisition_status(amended)["attempts"][amended.candidates[0]["candidate_id"]][0]["state"] == "retryable-operational-error"


def test_v4_preparation_backend_failure_keeps_exact_supports_and_postvalidation_blocks(context, tmp_path):
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=4)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    proof = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
        page_h3=h3, automated_screen=screen, backend=Backend(amended, error=True))
    failure = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
    assert failure["selected_page_h3_receipt_sha256"] == admission._sha(h3.read_bytes())
    # A different valid screen observation cannot replace the actual
    # failure's closed, hash-bound operation inputs in a resealed wrapper.
    alternate = tmp_path / "alternate-automatic-screen.json"
    admission.produce_automated_site_screen(alternate, amended, candidate_id=candidate["candidate_id"],
        navigation=navigation, page_h3=h3, selected_page_ordinal=0)
    changed = admission._unpack(proof.read_bytes(), admission.ATTEMPT_FAILURE_TYPE)
    changed["inputs"]["automated_screen"] = admission.import_evidence(amended.root, alternate)
    changed_proof = tmp_path / "resealed-operation.json"
    changed_proof.write_bytes(admission._json(admission._bind(admission.ATTEMPT_FAILURE_TYPE, changed)))
    with pytest.raises(ValueError, match="actual retained operation"):
        admission.unsuccessful_attempt_failure_facts(changed_proof, amended, candidate["candidate_id"])
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
        root_surveys=roots, attempt_failure=proof, automated_screen=screen)
    assert admission.verify_site_terminal(terminal, amended)["selected_page_h3_proof"]["outcome"] == "known-valid"
    class InvalidManifest(Backend):
        def prepare(self, *args, **kwargs):
            result = super().prepare(*args, **kwargs)
            result.prepared.path.write_bytes(admission._json({"schema_version": 999}))
            return result
    with pytest.raises(ValueError):
        admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
            page_h3=h3, automated_screen=screen, backend=InvalidManifest(amended))
    failed = sorted((amended.root / "attempts" / candidate["candidate_id"]).iterdir())[-1]
    assert (failed / "operational-error.json").exists() and not (failed / "attempt-failure.json").exists()


@pytest.mark.parametrize("bad_control", [False, True])
def test_v4_exact_page_negative_requires_independent_passing_controls(context, tmp_path, monkeypatch, bad_control):
    candidate, navigation, _h3, _ = _page_files(context, tmp_path)
    roots = _root_logs(context, tmp_path)
    amended = _amended_context(context, tmp_path, revision=4)
    from qcsd_lab import h3_prebaseline
    monkeypatch.setenv("QCSD_PUBLIC_ORIGIN_ONLY", "1")
    def negative(url):
        value = _probe(url)
        if url == f"https://{candidate['domain']}/" or bad_control:
            output = json.loads(value["output_text"])
            output["resources"][0]["known_valid"] = False
            raw = json.dumps(output)
            value.update(output_text=raw, output_sha256=admission._sha(raw.encode()), known_valid=False, outcome="ambiguous")
        return value
    monkeypatch.setattr(h3_prebaseline, "_run_one", negative)
    args = SimpleNamespace(command="probe-page", navigation=navigation, selected_page_ordinal=0)
    if bad_control:
        with pytest.raises(ValueError, match="controls"):
            rapid_acquire._page_action(amended, candidate["candidate_id"], args)
        assert not any(amended.root.rglob("attempt-failure.json"))
    else:
        proof = rapid_acquire._page_action(amended, candidate["candidate_id"], args)
        facts = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
        assert facts["controlled_page_probe"]["selected_page_ordinal"] == 0
        assert facts["selected_page_h3_receipt_sha256"] is None
        terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
                                                   root_surveys=roots, attempt_failure=proof)
        assert admission.verify_site_terminal(terminal, amended)["selected_page_h3_proof"] is None


def test_v3_cannot_promote_v4_live_attempt_receipt(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=3)
    with pytest.raises(ValueError, match="revision 4"):
        admission.produce_site_terminal(amended, candidate_id=amended.candidates[0]["candidate_id"],
                                       attempt_failure=tmp_path / "old-error.json")


@pytest.mark.parametrize("preparation", [False, True])
def test_v4_typed_primary_with_validation_cause_cannot_escape_through_legacy_catches(context, tmp_path, monkeypatch, preparation):
    amended = _amended_context(context, tmp_path, revision=4)
    def invalid(*_args, **_kwargs):
        try:
            raise ValueError("actual configuration guard failure")
        except ValueError as cause:
            raise _render_failure() from cause
    if preparation:
        candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
        backend = Backend(amended)
        backend.prepare = invalid
        with pytest.raises(Exception, match="actual typed hard cap"):
            admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
                page_h3=h3, automated_screen=screen, backend=backend)
    else:
        monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", invalid)
        with pytest.raises(Exception, match="actual typed hard cap"):
            rapid_acquire._page_action(amended, amended.candidates[0]["candidate_id"], SimpleNamespace(command="navigate"))
    assert not any(amended.root.rglob("attempt-failure.json"))
    assert not any(amended.root.rglob("page-policy-failure.json"))
    assert not any(amended.root.rglob("collector-failure.json"))
    assert any(amended.root.rglob("operational-error.json"))
    assert admission.acquisition_status(amended)["formal_trace_target"] == 16_000
