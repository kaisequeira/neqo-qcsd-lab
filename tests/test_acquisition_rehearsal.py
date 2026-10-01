"""The live rehearsal is bounded and cannot publish class-study evidence."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.class_acquisition import NavigationDiscovery
from qcsd_lab.acquisition_errors import RecoverableAcquisitionError
from qcsd_lab.class_catalogue import DiscoveredLink
from tools import acquisition_rehearsal as rehearsal


def _navigation(domain: str) -> NavigationDiscovery:
    homepage = f"https://{domain}/"
    site_origin = f"https://{domain}"
    return NavigationDiscovery(
        registrable_domain=domain,
        links=(),
        observed_origins=(site_origin,),
        page_observed_origins=((homepage, (site_origin,)),),
    )


def _events(root: Path) -> list[dict]:
    return [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]


def test_long_trace_is_preserved_without_flooding_terminal(tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    log = rehearsal._EventLog(path)
    try:
        log.emit("root-cdp-trace", recent_protocol_events=[{"detail": "x" * 5000}])
    finally:
        log.close()

    original = path.read_text(encoding="utf-8").rstrip("\n")
    assert json.loads(original)["recent_protocol_events"][0]["detail"] == "x" * 5000
    displayed = json.loads(capsys.readouterr().out)
    assert displayed["detail_path"] == str(path)
    assert displayed["detail_sha256"] == sha256(original.encode("utf-8")).hexdigest()
    assert displayed["detail_chars"] == len(original)
    assert len(json.dumps(displayed)) < 1000


def test_failed_prepare_tempfiles_are_copied_before_cleanup_with_bounds(tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    prepare_root = root / "prepared" / "diagnostic-test"
    prepare_root.mkdir(parents=True)
    events = rehearsal._EventLog(root / "events.jsonl")
    original_tempfile = rehearsal.preparation_module.tempfile
    temporary = None
    try:
        with pytest.raises(RuntimeError, match="real Neqo failure"):
            with rehearsal._capture_failed_prepare_tempfiles(
                output_root=root, prepare_root=prepare_root,
                workload_id="diagnostic-test", events=events,
                page_label={"page_url": "https://example.test/"},
            ):
                with rehearsal.preparation_module.tempfile.TemporaryDirectory(
                    prefix=".diagnostic-test-prepare-", dir=prepare_root,
                ) as temporary:
                    path = Path(temporary)
                    (path / "probe.log").write_bytes(b"a" * 200_000 + b"terminal-error")
                    (path / "probe-head").write_text("head", encoding="utf-8")
                    (path / "stability-0").mkdir()
                    (path / "stability-0" / "run.json").write_text(
                        '{"test": true}', encoding="utf-8"
                    )
                    for index in range(20):
                        (path / f"extra-{index:02d}.json").write_bytes(b"x" * 70_000)
                    raise RuntimeError("real Neqo failure")
    finally:
        events.close()
    assert rehearsal.preparation_module.tempfile is original_tempfile
    assert temporary is not None and not Path(temporary).exists()
    event = next(
        item for item in _events(root)
        if item["stage"] == "failed-prepare-artifacts-preserved"
    )
    assert event["scientific_credit"] is False
    assert event["file_count"] <= rehearsal.MAX_FAILED_PREPARE_FILES
    assert event["preserved_bytes"] <= rehearsal.MAX_FAILED_PREPARE_TOTAL_BYTES
    assert event["candidate_files_truncated"] is True
    saved = [Path(item["path"]) for item in event["files"]]
    assert all(path.is_file() and root in path.parents for path in saved)
    assert any(path.name == "probe-head" for path in saved)
    assert any(path.name == "run.json" for path in saved)
    assert next(path for path in saved if path.name == "probe.log").read_bytes().endswith(
        b"terminal-error"
    )
    assert not (root / "checkpoint.json").exists()


def test_successful_prepare_tempfiles_are_removed_without_diagnostic_copy(tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    prepare_root = root / "prepared" / "diagnostic-test"
    prepare_root.mkdir(parents=True)
    events = rehearsal._EventLog(root / "events.jsonl")
    try:
        with rehearsal._capture_failed_prepare_tempfiles(
            output_root=root, prepare_root=prepare_root,
            workload_id="diagnostic-test", events=events, page_label={},
        ):
            with rehearsal.preparation_module.tempfile.TemporaryDirectory(
                prefix=".diagnostic-test-prepare-", dir=prepare_root,
            ) as temporary:
                (Path(temporary) / "probe.log").write_text("success")
    finally:
        events.close()
    assert not Path(temporary).exists()
    assert not (root / "failed-prepare-artifacts").exists()


def test_target_pair_must_match_catalogue_and_cannot_repeat(monkeypatch, tmp_path):
    catalogue = (
        SimpleNamespace(candidate_id="tranco-0000001", domain="example.com"),
        SimpleNamespace(candidate_id="tranco-0000002", domain="other.example"),
    )
    monkeypatch.setattr(
        rehearsal, "load_candidate_catalogue_receipt", lambda _path: ({}, catalogue)
    )
    targets = rehearsal._validated_targets(
        ("tranco-0000001=example.com|https://example.com/",), tmp_path / "unused"
    )
    assert targets == (
        rehearsal.Target("tranco-0000001", "example.com", "https://example.com/"),
    )
    with pytest.raises(ValueError, match="exact frozen catalogue pair"):
        rehearsal._validated_targets(("tranco-0000001=other.example",), tmp_path)
    with pytest.raises(ValueError, match="repeated candidate ID"):
        rehearsal._validated_targets(
            ("tranco-0000001=example.com", "tranco-0000001=example.com"), tmp_path
        )
    with pytest.raises(ValueError, match="between 1 and 6"):
        rehearsal._validated_targets(("tranco-0000001=example.com",) * 7, tmp_path)


def test_output_is_create_only_and_outside_checkout(tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    assert root.is_dir()
    with pytest.raises(ValueError, match="create-only"):
        rehearsal._new_output_root(root)
    with pytest.raises(ValueError, match="outside the Lab checkout"):
        rehearsal._new_output_root(rehearsal.LAB_ROOT / "artifacts" / "diagnostic")


def test_real_rehearsal_binds_executable_neqo_bytes(monkeypatch, tmp_path):
    client = tmp_path / "neqo-qcsd-client"
    client.write_bytes(b"#!/bin/sh\nexit 0\n")
    client.chmod(0o700)
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(client))
    binding = rehearsal._neqo_client_binding(rehearsal.ExistingAcquisitionBackend)
    assert binding == {
        "kind": "real-neqo-client",
        "path": str(client.resolve()),
        "sha256": sha256(client.read_bytes()).hexdigest(),
        "size_bytes": client.stat().st_size,
    }
    client.write_bytes(b"#!/bin/sh\nexit 1\n")
    assert rehearsal._neqo_client_binding(rehearsal.ExistingAcquisitionBackend) != binding
    client.unlink()
    with pytest.raises(ValueError, match="absolute regular file"):
        rehearsal._neqo_client_binding(rehearsal.ExistingAcquisitionBackend)


def test_live_backend_path_logs_every_stage_without_formal_receipts(monkeypatch, tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: (image, {"image_digest": image}))
    observed: list[str] = []

    class Backend:
        def __init__(self, *, timeout_ms):
            assert timeout_ms == 60_000

        def discover_navigation(self, domain):
            observed.append("navigation")
            return _navigation(domain)

        def screen_h3(self, candidate_id, domain, navigation, pages):
            observed.append("h3-screen")
            assert candidate_id == "tranco-0000001"
            assert [page.url for page in pages] == ["https://example.com/"]
            return {}

        def prepare(self, workload_id, url, approved, output, *, origin_ip_pins):
            observed.append("prepare")
            assert workload_id.startswith("diagnostic-tranco-0000001-p00-")
            assert url == "https://example.com/"
            assert approved == ("https://example.com",)
            assert origin_ip_pins == {"https://example.com": "1.1.1.1"}
            assert root in output.parents
            output.mkdir()
            manifest = output / "prepared.json"
            manifest.write_text("{}\n", encoding="utf-8")
            return SimpleNamespace(prepared=SimpleNamespace(path=manifest))

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda _receipt, **_kwargs: {
            "screen_schema_version": 2,
            "decision": "pass",
            "control_before": {"outcome": "known-valid"},
            "control_after": {"outcome": "known-valid"},
            "page_attempts": [{
                "url": "https://example.com/",
                "attempts": [
                    {"outcome": "known-valid"}, {"outcome": "known-valid"},
                ],
            }],
        },
    )
    monkeypatch.setattr(
        rehearsal, "_converge_origins",
        lambda _backend, _url, *, seed_origins: (
            (("https://example.com",), SimpleNamespace(
                observed_origins=("https://example.com",),
                origin_ip_pins={"https://example.com": "1.1.1.1"},
            )) if seed_origins == ("https://example.com",) else pytest.fail("wrong seeds")
        ),
    )

    def validate(prepared, *, workload_id, approved_origins, origin_ip_pins):
        observed.append("deep-validation")
        assert prepared.prepared.path.is_file()
        assert workload_id.startswith("diagnostic-")
        assert approved_origins == ("https://example.com",)
        assert origin_ip_pins == {"https://example.com": "1.1.1.1"}
        return {"manifest_sha256": "f" * 64}

    monkeypatch.setattr(rehearsal, "_validate_prepared", validate)
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
    )
    assert result["successful_pages"] == 1
    assert result["h3_pass_prepared_pages"] == 1
    assert result["h3_override_prepared_pages"] == 0
    assert result["neqo_client"] == {"kind": "injected-backend-test-double"}
    assert result["diagnostic_outcome"] == "passing-screen-prepare"
    assert observed == ["navigation", "h3-screen", "prepare", "deep-validation"]
    stages = [event["stage"] for event in _events(root)]
    assert stages == [
        "run-start", "candidate-start", "navigation-complete",
        "h3-screen-receipt-preserved", "h3-screen-complete",
        "origin-convergence-start", "origin-convergence-complete", "prepare-start",
        "prepare-complete", "prepared-validation-complete", "run-complete",
    ]
    assert all(event["scientific_credit"] is False for event in _events(root))
    assert next(
        event for event in _events(root) if event["stage"] == "h3-screen-complete"
    )["page_outcomes"] == [{
        "url": "https://example.com/",
        "attempts": ["known-valid", "known-valid"],
    }]
    assert not (root / "checkpoint.json").exists()
    assert not (root / "provenance.json").exists()


def test_v2_rehearsal_prepares_first_eligible_page_after_nonvalid_first_page(
    monkeypatch, tmp_path
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: (image, {"image_digest": image}))
    alternate = "https://example.com/alternate"
    prepared_urls = []

    class Backend:
        def __init__(self, *, timeout_ms):
            assert timeout_ms == 60_000

        def discover_navigation(self, domain):
            return NavigationDiscovery(
                registrable_domain=domain,
                links=(DiscoveredLink(alternate, "text/html"),),
                observed_origins=("https://example.com",),
                page_observed_origins=(
                    ("https://example.com/", ("https://example.com",)),
                    (alternate, ("https://example.com",)),
                ),
            )

        def screen_h3(self, *_args):
            return {}

        def prepare(self, workload_id, url, approved, output, *, origin_ip_pins):
            prepared_urls.append(url)
            output.mkdir()
            manifest = output / "prepared.json"
            manifest.write_text("{}\n", encoding="utf-8")
            return SimpleNamespace(prepared=SimpleNamespace(path=manifest))

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda _receipt, **_kwargs: {
            "screen_schema_version": 2,
            "decision": "pass",
            "control_before": {"outcome": "known-valid"},
            "control_after": {"outcome": "known-valid"},
            "page_attempts": [
                {"url": "https://example.com/", "attempts": [
                    {"outcome": "timeout"}, {"outcome": "timeout"},
                ]},
                {"url": alternate, "attempts": [
                    {"outcome": "known-valid"}, {"outcome": "known-valid"},
                ]},
            ],
        },
    )
    monkeypatch.setattr(
        rehearsal, "_converge_origins",
        lambda _backend, _url, *, seed_origins: (
            ("https://example.com",),
            SimpleNamespace(
                observed_origins=("https://example.com",),
                origin_ip_pins={"https://example.com": "1.1.1.1"},
            ),
        ),
    )
    monkeypatch.setattr(
        rehearsal, "_validate_prepared",
        lambda *_args, **_kwargs: {"manifest_sha256": "f" * 64},
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root,
        max_pages=1,
        backend_factory=Backend,
        total_timeout_seconds=10,
    )
    assert result["successful_pages"] == 1
    assert prepared_urls == [alternate]
    assert next(
        event for event in _events(root) if event["stage"] == "h3-screen-complete"
    )["page_outcomes"] == [
        {"url": "https://example.com/", "attempts": ["timeout", "timeout"]},
        {"url": alternate, "attempts": ["known-valid", "known-valid"]},
    ]


def test_h3_site_rejection_is_reported_without_prepare(monkeypatch, tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: (image, {"image_digest": image}))

    class Backend:
        def __init__(self, *, timeout_ms):
            pass

        def discover_navigation(self, domain):
            return _navigation(domain)

        def screen_h3(self, *_args):
            raise rehearsal.H3SiteUnavailable({})

        def prepare(self, *_args, **_kwargs):
            pytest.fail("site rejection reached preparation")

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda _receipt, **_kwargs: {
            "decision": "site-rejection",
            "control_before": {"outcome": "known-valid"},
            "control_after": {"outcome": "known-valid"},
            "origin_attempts": [],
        },
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
    )
    assert result["successful_pages"] == 0
    assert result["failed_targets"] == 1
    assert [event["decision"] for event in _events(root)
            if event["stage"] == "h3-screen-complete"] == ["site-rejection"]
    preserved = next(
        event for event in _events(root)
        if event["stage"] == "h3-screen-receipt-preserved"
    )
    receipt_path = Path(preserved["h3_screen_diagnostic_path"])
    assert json.loads(receipt_path.read_text()) == {}
    assert rehearsal.sha256_file(receipt_path) == preserved["h3_screen_diagnostic_sha256"]


def test_selected_page_h3_diagnostic_keeps_exact_url_result_separate_from_screen(
    monkeypatch, tmp_path,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: (image, {"image_digest": image}))
    page_url = "https://example.com/articles/one"
    probe_urls: list[str] = []

    def probe(url):
        probe_urls.append(url)
        return {
            "url": url,
            "outcome": "ambiguous" if url == "https://example.com/" else "known-valid",
            "known_valid": url != "https://example.com/",
            "stdout_excerpt": "synthetic diagnostic",
        }

    monkeypatch.setattr(rehearsal, "_run_one", probe)

    class Backend:
        def __init__(self, *, timeout_ms):
            assert timeout_ms == 60_000

        def discover_navigation(self, domain):
            assert domain == "example.com"
            return NavigationDiscovery(
                registrable_domain=domain,
                links=(DiscoveredLink(page_url, "text/html"),),
                observed_origins=("https://example.com",),
                page_observed_origins=(
                    ("https://example.com/", ("https://example.com",)),
                    (page_url, ("https://example.com",)),
                ),
            )

        def screen_h3(self, *_args):
            raise rehearsal.H3ScreenBlocked({"formal": "blocked"})

        def prepare(self, *_args, **_kwargs):
            pytest.fail("diagnostic selected URL must not grant preparation admission")

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda _receipt, **_kwargs: {
            "decision": "blocked",
            "control_before": {"outcome": "known-valid"},
            "control_after": {"outcome": "known-valid"},
            "origin_attempts": [{
                "origin": "https://example.com",
                "attempts": [{"outcome": "ambiguous"}],
            }],
        },
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com", page_url),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
        probe_selected_page_h3=True,
    )
    assert probe_urls == [
        rehearsal.PREBASELINE_H3_SCREEN_CONTRACT["control_url"],
        "https://example.com/", page_url,
        rehearsal.PREBASELINE_H3_SCREEN_CONTRACT["control_url"],
    ]
    assert result["successful_pages"] == 0
    assert result["failed_targets"] == 1
    assert result["h3_screen_decision_counts"]["blocked"] == 1
    events = _events(root)
    comparison = next(
        item for item in events
        if item["stage"] == "selected-page-h3-diagnostic-complete"
    )
    assert comparison["root_outcome"] == "ambiguous"
    assert comparison["selected_outcome"] == "known-valid"
    assert comparison["bracketed_by_known_valid_controls"] is True
    assert comparison["formal_h3_admission_unchanged"] is True
    receipt = json.loads(Path(comparison["diagnostic_path"]).read_text())
    assert receipt["scientific_credit"] is False
    assert receipt["selected_url"] == page_url
    assert receipt["root_probe"]["url"] == "https://example.com/"
    assert receipt["selected_probe"]["url"] == page_url
    assert receipt["formal_h3_admission_unchanged"] is True
    assert rehearsal.sha256_file(Path(comparison["diagnostic_path"])) == comparison[
        "diagnostic_sha256"
    ]
    assert [item["stage"] for item in events].index(
        "selected-page-h3-diagnostic-complete"
    ) < [item["stage"] for item in events].index("h3-screen-complete")
    assert not (root / "checkpoint.json").exists()


def test_selected_page_h3_diagnostic_skips_candidate_when_control_fails(
    monkeypatch, tmp_path,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    calls: list[str] = []

    def probe(url):
        calls.append(url)
        return {"url": url, "outcome": "ambiguous"}

    monkeypatch.setattr(rehearsal, "_run_one", probe)
    events = rehearsal._EventLog(root / "events.jsonl")
    try:
        rehearsal._probe_selected_page_h3(
            root, attempt=1,
            target=rehearsal.Target("tranco-0000001", "example.com"),
            pages=(SimpleNamespace(url="https://example.com/article", ordinal=1),),
            events=events,
        )
    finally:
        events.close()
    assert calls == [rehearsal.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]]
    comparison = next(
        item for item in _events(root)
        if item["stage"] == "selected-page-h3-diagnostic-complete"
    )
    assert comparison["bracketed_by_known_valid_controls"] is False
    assert comparison["root_outcome"] is None
    assert comparison["selected_outcome"] is None
    receipt = json.loads(Path(comparison["diagnostic_path"]).read_text())
    assert receipt["root_probe"] is None
    assert receipt["selected_probe"] is None
    assert receipt["control_after"] is None
    assert receipt["scientific_credit"] is False


def test_all_selected_pages_h3_diagnostic_uses_one_bracket_and_one_root_per_origin(
    monkeypatch, tmp_path,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    control = rehearsal.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    pages = (
        SimpleNamespace(url="https://example.com/", ordinal=0),
        SimpleNamespace(url="https://example.com/one", ordinal=1),
        SimpleNamespace(url="https://www.example.com/two", ordinal=2),
    )
    calls: list[str] = []

    def probe(url):
        calls.append(url)
        return {
            "url": url,
            "outcome": "ambiguous" if url.endswith("/one") else "known-valid",
            "output_text": '{"raw": true}',
        }

    monkeypatch.setattr(rehearsal, "_run_one", probe)
    events = rehearsal._EventLog(root / "events.jsonl")
    try:
        rehearsal._probe_all_selected_pages_h3(
            root, attempt=1,
            target=rehearsal.Target("tranco-0000001", "example.com"),
            pages=pages, events=events,
        )
    finally:
        events.close()
    assert calls == [
        control,
        "https://example.com/", "https://example.com/",
        "https://example.com/one",
        "https://www.example.com/", "https://www.example.com/two",
        control,
    ]
    completion = next(
        item for item in _events(root)
        if item["stage"] == "all-selected-pages-h3-diagnostic-complete"
    )
    assert completion["bracketed_by_known_valid_controls"] is True
    assert completion["formal_h3_admission_unchanged"] is True
    assert [item["selected_outcome"] for item in completion["page_outcomes"]] == [
        "known-valid", "ambiguous", "known-valid",
    ]
    path = Path(completion["diagnostic_path"])
    receipt = json.loads(path.read_text())
    assert receipt["scientific_credit"] is False
    assert len(receipt["root_probes"]) == 2
    assert len(receipt["selected_pages"]) == 3
    assert receipt["selected_pages"][1]["probe"]["output_text"] == '{"raw": true}'
    assert receipt["control_before"]["url"] == control
    assert receipt["control_after"]["url"] == control
    assert rehearsal.sha256_file(path) == completion["diagnostic_sha256"]
    assert list((root / "diagnostic-selected-page-h3").iterdir()) == [path]
    with pytest.raises(FileExistsError):
        events = rehearsal._EventLog(root / "events-again.jsonl")
        try:
            rehearsal._probe_all_selected_pages_h3(
                root, attempt=1,
                target=rehearsal.Target("tranco-0000001", "example.com"),
                pages=pages, events=events,
            )
        finally:
            events.close()


def test_all_selected_pages_h3_diagnostic_is_bounded_and_control_fail_closed(
    monkeypatch, tmp_path,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    pages = tuple(
        SimpleNamespace(url=f"https://example.com/{index}", ordinal=index)
        for index in range(6)
    )
    calls: list[str] = []
    monkeypatch.setattr(
        rehearsal, "_run_one",
        lambda url: (calls.append(url) or {"url": url, "outcome": "ambiguous"}),
    )
    events = rehearsal._EventLog(root / "events.jsonl")
    try:
        with pytest.raises(ValueError, match="one to five"):
            rehearsal._probe_all_selected_pages_h3(
                root, attempt=1,
                target=rehearsal.Target("tranco-0000001", "example.com"),
                pages=pages, events=events,
            )
        rehearsal._probe_all_selected_pages_h3(
            root, attempt=1,
            target=rehearsal.Target("tranco-0000001", "example.com"),
            pages=pages[:5], events=events,
        )
    finally:
        events.close()
    assert calls == [rehearsal.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]]
    completion = next(
        item for item in _events(root)
        if item["stage"] == "all-selected-pages-h3-diagnostic-complete"
    )
    assert completion["bracketed_by_known_valid_controls"] is False
    assert all(item["selected_outcome"] is None for item in completion["page_outcomes"])
    receipt = json.loads(Path(completion["diagnostic_path"]).read_text())
    assert receipt["root_probes"] == {}
    assert receipt["control_after"] is None
    assert all(item["probe"] is None for item in receipt["selected_pages"])


def test_all_selected_pages_diagnostic_does_not_change_formal_h3_block(
    monkeypatch, tmp_path,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    page_url = "https://example.com/articles/one"
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: ("native", {}))
    monkeypatch.setattr(
        rehearsal, "_run_one",
        lambda url: {"url": url, "outcome": "known-valid"},
    )

    class Backend:
        def __init__(self, *, timeout_ms):
            pass

        def discover_navigation(self, domain):
            return NavigationDiscovery(
                registrable_domain=domain,
                links=(DiscoveredLink(page_url, "text/html"),),
                observed_origins=("https://example.com",),
                page_observed_origins=(
                    ("https://example.com/", ("https://example.com",)),
                    (page_url, ("https://example.com",)),
                ),
            )

        def screen_h3(self, *_args):
            raise rehearsal.H3ScreenBlocked({"formal": "blocked"})

        def prepare(self, *_args, **_kwargs):
            pytest.fail("all-page diagnostic changed formal admission")

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda _receipt, **_kwargs: {
            "decision": "blocked",
            "control_before": {"outcome": "known-valid"},
            "control_after": {"outcome": "known-valid"},
            "origin_attempts": [],
        },
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
        probe_all_selected_pages_h3=True,
    )
    assert result["successful_pages"] == 0
    assert result["failed_targets"] == 1
    assert result["h3_screen_decision_counts"]["blocked"] == 1
    completion = next(
        item for item in _events(root)
        if item["stage"] == "all-selected-pages-h3-diagnostic-complete"
    )
    assert [item["url"] for item in completion["page_outcomes"]] == [
        "https://example.com/", page_url,
    ]
    assert len(list((root / "diagnostic-selected-page-h3").iterdir())) == 1
    assert not (root / "checkpoint.json").exists()


@pytest.mark.parametrize(
    ("decision", "screen_exception"),
    (("site-rejection", "H3SiteUnavailable"), ("blocked", "H3ScreenBlocked")),
)
def test_explicit_h3_override_prepares_but_retains_nonpass_decision(
    monkeypatch, tmp_path, decision, screen_exception,
):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: (image, {"image_digest": image}))
    full_receipt = {"payload": {"decision": decision, "raw_attempt": "retained"}}
    calls: list[str] = []

    class Backend:
        def __init__(self, *, timeout_ms):
            assert timeout_ms == 60_000

        def discover_navigation(self, domain):
            return _navigation(domain)

        def screen_h3(self, *_args):
            calls.append("screen")
            raise getattr(rehearsal, screen_exception)(full_receipt)

        def prepare(self, workload_id, url, approved, output, *, origin_ip_pins):
            calls.append("prepare")
            output.mkdir()
            manifest = output / "prepared.json"
            manifest.write_text("{}\n", encoding="utf-8")
            return SimpleNamespace(prepared=SimpleNamespace(path=manifest))

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda value, **_kwargs: (
            {
                "decision": value["payload"]["decision"],
                "control_before": {"outcome": "known-valid"},
                "control_after": {"outcome": "known-valid"},
                "origin_attempts": [],
            }
        ),
    )
    monkeypatch.setattr(
        rehearsal, "_converge_origins",
        lambda _backend, _url, *, seed_origins: (
            (("https://example.com",), SimpleNamespace(
                observed_origins=("https://example.com",),
                origin_ip_pins={"https://example.com": "1.1.1.1"},
            )) if seed_origins == ("https://example.com",) else pytest.fail("wrong seeds")
        ),
    )
    monkeypatch.setattr(
        rehearsal, "_validate_prepared",
        lambda *_args, **_kwargs: {"manifest_sha256": "f" * 64},
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
        continue_after_h3_screen=True,
    )
    assert calls == ["screen", "prepare"]
    assert result["successful_pages"] == 1
    assert result["h3_pass_prepared_pages"] == 0
    assert result["h3_override_prepared_pages"] == 1
    assert result["failed_targets"] == 1
    assert result["diagnostic_outcome"] == "bypassed-screen-prepare-only"
    assert result["h3_screen_decision_counts"][decision] == 1
    events = _events(root)
    screened = next(event for event in events if event["stage"] == "h3-screen-complete")
    assert screened["decision"] == decision
    assert screened["continued_despite_nonpass"] is True
    path = Path(screened["h3_screen_diagnostic_path"])
    assert json.loads(path.read_text()) == full_receipt
    assert rehearsal.sha256_file(path) == screened["h3_screen_diagnostic_sha256"]
    prepared = next(
        event for event in events if event["stage"] == "prepared-validation-complete"
    )
    assert prepared["h3_screen_decision"] == decision
    assert prepared["h3_policy_overridden"] is True
    assert all(event["scientific_credit"] is False for event in events)
    assert not (root / "checkpoint.json").exists()
    assert not (root / "provenance.json").exists()


def test_invalid_h3_receipt_is_preserved_before_validation_fails(monkeypatch, tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: ("native", {}))

    class Backend:
        def __init__(self, *, timeout_ms):
            pass

        def discover_navigation(self, domain):
            return _navigation(domain)

        def screen_h3(self, *_args):
            return {"raw": "invalid-but-retained"}

        def prepare(self, *_args, **_kwargs):
            pytest.fail("invalid H3 receipt reached preparation")

    monkeypatch.setattr(
        rehearsal, "validate_h3_screen_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("invalid H3 receipt")),
    )
    result = rehearsal.run_rehearsal(
        (rehearsal.Target("tranco-0000001", "example.com"),),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
        continue_after_h3_screen=True,
    )
    assert result["successful_pages"] == 0
    errors = [event for event in _events(root) if event["stage"] == "candidate-error"]
    assert len(errors) == 1
    assert errors[0]["failed_stage"] == "h3-screen"
    path = Path(errors[0]["h3_screen_diagnostic_path"])
    assert json.loads(path.read_text()) == {"raw": "invalid-but-retained"}
    assert rehearsal.sha256_file(path) == errors[0]["h3_screen_diagnostic_sha256"]


def test_each_navigation_failure_is_retained_with_its_real_class(monkeypatch, tmp_path):
    root = rehearsal._new_output_root(tmp_path / "diagnostic")
    monkeypatch.setattr(rehearsal, "_runtime_source", lambda: ("native", {}))

    class Backend:
        def __init__(self, *, timeout_ms):
            pass

        def discover_navigation(self, domain):
            if domain == "first.example":
                raise RecoverableAcquisitionError("DNS lookup failed")
            raise RuntimeError("root CDP interception integrity failed")

    result = rehearsal.run_rehearsal(
        (
            rehearsal.Target("tranco-0000001", "first.example"),
            rehearsal.Target("tranco-0000002", "second.example"),
        ),
        output_root=root, backend_factory=Backend, total_timeout_seconds=10,
    )
    assert result["attempted_targets"] == 2
    assert result["successful_pages"] == 0
    assert result["failed_targets"] == 2
    errors = [event for event in _events(root) if event["stage"] == "candidate-error"]
    assert [(event["domain"], event["classification"], event["error_type"])
            for event in errors] == [
        ("first.example", "recoverable-external-failure", "RecoverableAcquisitionError"),
        ("second.example", "internal-or-infrastructure-error", "RuntimeError"),
    ]
    assert all(event["scientific_credit"] is False for event in errors)
    assert not list(root.rglob("*receipt*"))


def test_deep_prepared_check_rejects_rebound_result(monkeypatch, tmp_path):
    manifest = tmp_path / "prepared.json"
    manifest.write_text(json.dumps({
        "preparation": {
            "final_url": "https://example.com/",
            "approved_origins": ["https://example.com"],
            "origin_ip_pins": {"https://example.com": "1.1.1.1"},
        },
    }), encoding="utf-8")
    monkeypatch.setattr(rehearsal, "validate_class_study_preparation", lambda *_a, **_k: None)
    monkeypatch.setattr(
        rehearsal, "_prepared_primary_response",
        lambda _manifest: {"status": 200, "bytes": 100, "body_sha256": "b" * 64},
    )
    monkeypatch.setattr(rehearsal, "_prepared_replay_identity_sha256", lambda _m: "g" * 64)
    prepared = SimpleNamespace(
        prepared=SimpleNamespace(path=manifest, sha256=rehearsal.sha256_file(manifest)),
        final_url="https://example.com/", status=200, body_bytes=100,
        body_sha256="b" * 64, resource_graph_sha256="g" * 64,
        preparation_origin_ip_pins={"https://example.com": "1.1.1.1"},
    )
    verified = rehearsal._validate_prepared(
        prepared, workload_id="diagnostic-test",
        approved_origins=("https://example.com",),
        origin_ip_pins={"https://example.com": "1.1.1.1"},
    )
    assert verified["status"] == 200
    prepared.body_bytes = 101
    with pytest.raises(ValueError, match="differs from deeply revalidated"):
        rehearsal._validate_prepared(
            prepared, workload_id="diagnostic-test",
            approved_origins=("https://example.com",),
            origin_ip_pins={"https://example.com": "1.1.1.1"},
        )


def test_control_mode_uses_diagnostic_identity_and_no_catalogue(monkeypatch, tmp_path):
    observed: list[rehearsal.Target] = []
    options: list[tuple[bool, bool, bool]] = []

    def run(targets, **kwargs):
        observed.extend(targets)
        options.append((
            kwargs["continue_after_h3_screen"],
            kwargs["probe_selected_page_h3"],
            kwargs["probe_all_selected_pages_h3"],
        ))
        return {
            "successful_pages": 1,
            "h3_pass_prepared_pages": 0,
            "h3_override_prepared_pages": 1,
            "timed_out": False,
        }

    monkeypatch.setattr(rehearsal, "run_rehearsal", run)
    monkeypatch.setattr(
        rehearsal, "load_candidate_catalogue_receipt",
        lambda _path: pytest.fail("control mode read the candidate catalogue"),
    )
    assert rehearsal.main([
        "--control-domain", "cloudflare-quic.com",
        "--output-root", str(tmp_path / "diagnostic"),
        "--continue-after-h3-screen",
        "--probe-selected-page-h3",
    ]) == 3
    assert observed == [rehearsal.Target(
        "diagnostic-control", "cloudflare-quic.com", kind="diagnostic-control"
    )]
    assert options == [(True, True, False)]
    assert rehearsal.main([
        "--control-domain", "cloudflare-quic.com",
        "--output-root", str(tmp_path / "diagnostic-all"),
        "--probe-all-selected-pages-h3",
    ]) == 3
    assert options == [(True, True, False), (False, False, True)]
    assert rehearsal.main([
        "--control-domain", "cloudflare-quic.com",
        "--output-root", str(tmp_path / "diagnostic-invalid"),
        "--probe-selected-page-h3", "--probe-all-selected-pages-h3",
    ]) == 2
    assert not (tmp_path / "diagnostic-invalid").exists()
    with pytest.raises(ValueError, match="canonical lower-case"):
        rehearsal._validated_control("Cloudflare-Quic.com")
