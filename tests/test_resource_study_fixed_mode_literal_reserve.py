"""Connected literal-MAL preparation, using genuine frozen20 metadata bytes.

The real public enroll_fixed_mode, original parent/selection/literal inventory,
SQL, immutable input, Native preparation/qualification metadata readers and
enrollment publication run. Only external Docker/DNS/client execution and its
runtime-file replay are replaced. Synthetic network responses issue no credit.
"""
from contextlib import nullcontext, redirect_stdout
from copy import deepcopy
import base64
import hashlib
import io
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_fixed_mode_preparation as focused
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_runtime as runtime_backend
from qcsd_lab import resource_study_selection as selection
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study_lineage import enrollment as simple_enrollment
from tests import test_resource_study_native as network_fixture


FIXTURE = Path(__file__).parent / "fixtures/literal_MAL_original20_focused_preparation.json"
HOST = "cdn.myanimelist.net"


def put(path, value, *, raw=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    _create(path, value if raw else inputs.canonical_json(value))
    return {"path": str(path), "sha256": inputs.sha256_file(path)}


def actual_metadata():
    envelope = json.loads(FIXTURE.read_bytes())
    result = {}
    for name, spec in envelope["files"].items():
        raw = base64.b64decode(spec["raw_base64"], validate=True)
        assert len(raw) == spec["bytes"]
        assert hashlib.sha256(raw).hexdigest() == spec["sha256"]
        result[name] = raw
    assert hashlib.sha256(result["manifest.json"]).hexdigest() == "d978624c38916a3ac133df239c75f38eee6c38235003d7b37a409bfa5ba61dcb"
    assert "frozen_application_manifest" not in json.loads(result["prepared_workload.json"])["preparation"]
    return result


class HistoricalGET:
    """Synthetic network leaf; real original literal enrollment/preparation proof."""
    def __init__(self, root, raw, prepared, declared_runtime):
        self.root, self.raw = root, raw
        self.prepared, self.runtime = prepared, declared_runtime

    def prepare(self, candidate, output):
        base = output / "prepared"
        manifest = json.loads(self.raw)
        assert candidate["hostname"] == HOST
        assert candidate["urls"] == [row["url"] for row in manifest["resources"]]
        put(output / "job.json", {"hostname": HOST, "urls": candidate["urls"],
            "output": str(base), "runtime": self.runtime})
        input_ref = put(base / "preparation-get/input.json", manifest)
        run = network_fixture.get_run(manifest, input_ref["sha256"])
        run["migration_commit"] = self.runtime["native_commit"]
        run["endpoints"][0]["origin"] = "https://" + HOST + "/"
        run_ref = put(base / "preparation-get/native/run.json", run)
        put(base / "preparation-get/completed.json", {"returncode": 0,
            "timed_out": False, "client_unchanged": True,
            "client_sha256": self.runtime["client_sha256"]})
        prepared = deepcopy(self.prepared)
        prepared["preparation"].update(runtime=self.runtime,
            actual_preparation_run="preparation-get/native/run.json",
            actual_preparation_run_sha256=run_ref["sha256"],
            expected_responses=[{key: row[key] for key in
                ("resource_id", "status", "bytes", "body_sha256")} for row in run["responses"]])
        put(base / "resources.json", self.raw, raw=True)
        put(base / "prepared-workload.json", prepared)
        paths = native._parameter_bundle(base)
        for path in base.rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        relative = base.relative_to(self.root).as_posix()
        return {"schema_version": 1, "role": native.ROLE, "hostname": HOST,
            "urls": candidate["urls"], "runtime": self.runtime,
            "workload_path": relative + "/resources.json",
            "workload_sha256": hashlib.sha256(self.raw).hexdigest(),
            "preparation_dir": relative,
            "paths": {"manifest": relative + "/resources.json",
                "prepared_workload": relative + "/prepared-workload.json",
                **{key: path.relative_to(self.root).as_posix() for key, path in paths.items()}},
            "files": {path.relative_to(self.root).as_posix(): inputs.sha256_file(path)
                for path in base.rglob("*") if path.is_file()},
            "mode_settings": native._mode_settings(paths), "mode_policies": native.mode_policies(),
            "mode_readiness": {mode: mode == "undefended" for mode in inputs.MODES},
            "source_occurrences": deepcopy(candidate["source_occurrences"]),
            "scientific_credit": False}


@pytest.fixture
def literal_case(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve(strict=True)
    actual = actual_metadata()
    manifest = json.loads(actual["manifest.json"])
    urls = [row["url"] for row in manifest["resources"]]
    historical_prepared = json.loads(actual["prepared_workload.json"])
    old_runtime = json.loads(actual["enrollment.json"])["runtime"]
    canonical_raw = (Path(__file__).parent / "fixtures/native142_sdk121_canonical_runtime.json").read_bytes()
    assert hashlib.sha256(canonical_raw).hexdigest() == focused.CANONICAL142_SHA256
    canonical = json.loads(canonical_raw)
    runtime = {"canonical_sha256": focused.CANONICAL142_SHA256,
        "client_sha256": canonical["installed_client_sha256"], "platform": canonical["platform"],
        "native_commit": canonical["source"]["neqo_commit"], "source": canonical["source"],
        "collection_image_digest": canonical["collection_image_digest"],
        "prepare_image_digest": canonical["prepare_image_digest"]}
    # No external Docker operation is used by these disposable metadata roots.
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    monkeypatch.setattr(runtime_backend, "docker_lock", nullcontext)
    monkeypatch.setattr(study, "runtime_identity", lambda path: deepcopy(runtime))
    source = tmp_path / "source.json"
    hosts = ["alpha.example", lineage.EXCLUDED, *[f"literal-control-{i:02d}.example" for i in range(48)]]
    put(source, [{"crUX_domain": "fixture.example", "resources": [
        {"resource_domain": host, "resource_urls": [f"https://{host}/r?i={i}" for i in range(20)]}
        for host in hosts]}])
    parent = StudyStore(tmp_path / "parent")
    study.initialize(source, parent.root)
    ancestor = simple_enrollment(parent, "alpha.example")
    original_enrollment = json.loads(actual["enrollment.json"])
    ancestor["runtime"] = deepcopy(old_runtime)
    ancestor["mode_settings"] = deepcopy(original_enrollment["mode_settings"])
    ancestor["mode_policies"] = deepcopy(original_enrollment["mode_policies"])
    parent.enroll(ancestor)
    cells = {("alpha.example", mode): epochs._cell(parent, "alpha.example", mode) for mode in inputs.MODES}
    epochs._bind(parent, parent)
    epochs._publish(parent, [], cells, "initial", cells)
    inventory = tmp_path / "literal-MAL.json"
    put(inventory, {"urls": [{"url": url} for url in urls]})
    historical = StudyStore(tmp_path / "historical-literal")
    lineage.initialize(parent.root, historical.root, inventory, storage_reserve_bytes=2 * 1024**3)
    result = study.enroll(historical.root, old_runtime, [HOST],
        backend=HistoricalGET(historical.root, actual["manifest.json"], historical_prepared, old_runtime))
    assert result["enrollment"] == [{"hostname": HOST, "status": "enrolled", "resources": 20}]
    epochs.create_epoch(parent.root, historical.root, change="replace-unused-class",
        affected_hostnames=[HOST], affected_modes=["undefended"])
    root = tmp_path / "fresh-focused"
    cohorts.initialize_cohort(parent.root, root)
    old_path = historical.root / "classes" / HOST / "enrollment.json"
    old = json.loads(old_path.read_bytes())
    canonical_ref = put(tmp_path / "actual142-canonical.json", canonical_raw, raw=True)
    operations, jobs = [], []
    client = tmp_path / "runtime-client-placeholder"
    client.write_bytes(b"runtime-file boundary; never executed\n")

    def network_execute(command, directory, *, timeout, client_sha256):
        operations.append(command[1])
        if command[1] == "run":
            path = Path(command[command.index("--workload") + 1])
            body = json.loads(path.read_bytes())
            run = network_fixture.get_run(body, inputs.sha256_file(path))
            run["migration_commit"] = focused.NATIVE142
            run["endpoints"][0]["origin"] = "https://" + HOST + "/"
            put(directory / "native/run.json", run)
        else:
            assert command[1] == "qualify-chaff-response"
            prepared_path = Path(command[command.index("--workload") + 1])
            identifier = int(command[command.index("--selected-chaff-resource-id") + 1])
            index = int(directory.name.split("-")[-1])
            receipt = network_fixture.response_receipt(prepared_path, identifier, index)
            receipt["source"]["migration_commit"] = focused.NATIVE142
            put(directory / "native/qualification.json", receipt)
        completed = {"returncode": 0, "timed_out": False,
            "client_unchanged": True, "client_sha256": client_sha256}
        put(directory / "completed.json", completed)
        return completed

    def docker(*argv, **kwargs):
        assert argv[0] == "run"
        job_path = Path(argv[-1])
        jobs.append(json.loads(job_path.read_bytes()))
        output = io.StringIO()
        with redirect_stdout(output):
            focused.native_main(str(job_path))
        return output.getvalue()

    monkeypatch.setattr(native, "_runtime", lambda bound, _: (client, deepcopy(bound)))
    monkeypatch.setattr(native, "_execute", network_execute)
    monkeypatch.setattr(runtime_backend, "_runtime_check", lambda _: {"NCPU": 24})
    monkeypatch.setattr(runtime_backend, "public_ipv4", lambda host: {"hostname": host, "selected_ipv4": "192.0.2.1"})
    monkeypatch.setattr(runtime_backend, "_docker", docker)

    def request(mode, *, reverse_selection=False):
        chosen = selection.make_manifest(root, HOST, urls)
        if reverse_selection:
            chosen["urls"] = list(reversed(chosen["urls"]))
        selected = put(tmp_path / "selection.json", chosen)
        context, _ = cohorts._input_context(root, StudyStore(root).plan())
        value = {"record_type": focused.INPUT, "schema_version": 1, "root": str(root),
            "parent": {**context["parent"], "head_sha256": context["predecessor_sha256"]},
            "hostname": HOST, "mode": mode, "historical_root": str(historical.root),
            "historical_enrollment": {"path": str(old_path), "sha256": inputs.sha256_file(old_path)},
            "runtime": runtime, "science": focused._science(old, mode),
            "source_contract": cohorts.verifier_contract(), "canonical_runtime": canonical_ref,
            "resource_selection": selected, "scientific_credit": False}
        return value, put(tmp_path / "focused-input.json", value)
    return {"root": root, "runtime": runtime, "request": request,
        "operations": operations, "jobs": jobs, "actual": actual, "urls": urls,
        "historical_prepared": historical_prepared}


@pytest.mark.parametrize("mode", ["front", "tamaraw"])
def test_public_literal_MAL_fixed_mode_keeps_exact_bytes_and_original_readers(literal_case, mode):
    case = literal_case
    _, ref = case["request"](mode)
    result = focused.enroll_fixed_mode(case["root"], case["runtime"],
        input_path=Path(ref["path"]), input_sha256=ref["sha256"])
    assert result["status"] == "enrolled" and result["scientific_credit"] is False
    assert case["operations"] == ["run", *["qualify-chaff-response"] * 3]
    job, = case["jobs"]
    assert job["literal_reserve"] is True
    assert Path(job["frozen_manifest"]).read_bytes() == case["actual"]["manifest.json"]
    enrollment = json.loads((case["root"] / "classes" / HOST / "enrollment.json").read_bytes())
    assert enrollment["urls"] == case["urls"]
    assert (case["root"] / enrollment["workload_path"]).read_bytes() == case["actual"]["manifest.json"]
    assert "frozen_application_manifest" not in enrollment
    assert cohorts.INPUT_AUTHORITY_KEY not in enrollment
    assert cohorts.INPUT_CONTEXT not in enrollment["files"]
    assert selection.validate_selection_proof(case["root"], enrollment)["scientific_credit"] is False
    lineage.validate_enrollment(StudyStore(case["root"]), enrollment)
    epochs._verify_preparation(StudyStore(case["root"]), HOST)
    with pytest.raises(ValueError, match="literal-reserve reader"):
        selection._frozen_application_manifest_context(case["root"], HOST,
            case["urls"], enrollment["workload_sha256"])
    assert StudyStore(case["root"]).status()["accepted_count"] == 0


def test_public_literal_MAL_reversed_selection_refuses_before_network(literal_case):
    case = literal_case
    _, ref = case["request"]("front", reverse_selection=True)
    with pytest.raises(ValueError, match="order"):
        focused.enroll_fixed_mode(case["root"], case["runtime"],
            input_path=Path(ref["path"]), input_sha256=ref["sha256"])
    assert case["operations"] == case["jobs"] == []


@pytest.mark.parametrize("flag,hostname", [(False, HOST), (0, HOST), (1, HOST),
    (None, HOST), (True, "other.example")])
def test_literal_job_flag_is_typed_and_bound_to_original_hostname(tmp_path, flag, hostname):
    actual = actual_metadata()
    prepared = json.loads(actual["prepared_workload.json"])
    job = {"record_type": focused.INPUT, "hostname": hostname, "mode": "front",
        "urls": [row["url"] for row in json.loads(actual["manifest.json"])["resources"]],
        "output": str(tmp_path / "no-output"), "runtime": prepared["preparation"]["runtime"],
        "science": {}, "frozen_manifest": str(tmp_path / "never-opened.json"),
        "frozen_manifest_sha256": "0" * 64, "historical_prepared": prepared,
        "consumer_checkout": str(Path(focused.__file__).resolve(strict=True).parents[2]),
        "source_contract": cohorts.verifier_contract(), "scientific_credit": False}
    if flag is not None:
        job["literal_reserve"] = flag
    ref = put(tmp_path / "bad-job.json", job)
    with pytest.raises(ValueError, match="foreign consumer or job|literal-reserve job"):
        focused.native_main(ref["path"])
    assert not (tmp_path / "no-output").exists()
