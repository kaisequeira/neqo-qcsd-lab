#!/usr/bin/env python3
"""Create first-site rolling inputs and exact commands; never launch Docker here.

The separately invoked qualify-image command runs inside the declared installed
collection image and uses the existing public one-workload qualification API.
All formal authority remains in tools/rapid_rolling_capture.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def read(path):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"expected regular unlinked file: {path}")
    return path.read_bytes()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"


def ref(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": sha(read(path))}


def checked(reference):
    if set(reference) != {"path", "sha256"}:
        raise ValueError("file reference fields differ")
    raw = read(reference["path"])
    if sha(raw) != reference["sha256"]:
        raise ValueError("bound input bytes changed")
    return raw


def create(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("linked source or application evidence")
        if path.is_file():
            result[relative.as_posix()] = {"sha256": sha(read(path)), "executable": bool(path.stat().st_mode & 0o111)}
    return result


def checked_runtime(args):
    build, clean = args.runtime_build_root.absolute(), args.clean_runtime_root.absolute()
    canonical_ref = {"path": str(build / "canonical-runtime.json"), "sha256": args.canonical_sha256}
    canonical = json.loads(checked(canonical_ref))
    source = json.loads(checked({"path": str(build / "runtime-export/source.json"),
                                "sha256": canonical["exported_source_manifest_sha256"]}))
    source_files = json.loads(checked({"path": str(build / "source-inventory.json"),
                                      "sha256": canonical["source_inventory_sha256"]}))
    if (source != canonical["source"] or source["lab_commit"] != args.expected_lab_commit
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["neqo_commit"] != source["neqo_pinned_commit"]
        or source["image_digest"] is not None
        or canonical["installed_byte_verification_completed"] is not True
        or inventory(clean) != source_files or inventory(build / "image-context/source") != source_files):
        raise ValueError("actual installed runtime and clean source identity differ")
    for argv, expected in ((["git", "rev-parse", "HEAD"], source["lab_commit"]),
                           (["git", "-C", "neqo-qcsd", "rev-parse", "HEAD"], source["neqo_commit"])):
        if subprocess.check_output(argv, cwd=clean, text=True).strip() != expected:
            raise ValueError("clean source Git identity differs")
    for suffix in ([], ["-C", "neqo-qcsd"]):
        if subprocess.check_output(["git", *suffix, "status", "--porcelain"], cwd=clean):
            raise ValueError("runtime source checkout is dirty")
    checked({"path": str(build / "runtime-export/neqo-qcsd-client"), "sha256": canonical["installed_client_sha256"]})
    for role in ("collection", "prepare"):
        proof = canonical["checks"][role]
        completed = json.loads(read(build / f"{role}-installed-verification-completed.json"))
        stdout, stderr = read(build / f"{role}-installed-verification.stdout.log"), read(build / f"{role}-installed-verification.stderr.log")
        if (type(completed["returncode"]) is not int or completed["returncode"] != 0
            or completed["stdout_sha256"] != sha(stdout) or completed["stderr_sha256"] != sha(stderr)
            or json.loads(stdout) != proof or proof["source"] != source
            or proof["client_sha256"] != canonical["installed_client_sha256"]
            or proof["image_digest"] != canonical[f"{role}_image_digest"]):
            raise ValueError("installed image lacks its real matching successful closure")
    return canonical_ref, canonical, clean


def stage(args):
    if sys.version_info < (3, 11) or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name) is None:
        raise ValueError("stage requires Python >=3.11 and a safe lowercase name")
    if len(set(args.modes)) != len(args.modes):
        raise ValueError("requested ready settings must be unique")
    subprocess.run([str(args.python.absolute()), "-I", "-c", "import sys; assert sys.version_info >= (3,11)"], check=True)
    output, data, acquisition = args.output.absolute(), args.data_root.absolute(), args.acquisition_root.absolute()
    if output.exists() or not data.is_dir() or not output.is_relative_to(data) or not acquisition.is_relative_to(data):
        raise ValueError("fresh output and retained admission must share the explicitly mounted data root")
    canonical_ref, canonical, clean = checked_runtime(args)
    old = args.original_canary_root.absolute()
    for protected in (clean, args.runtime_build_root.absolute(), acquisition, old):
        if output == protected or output.is_relative_to(protected) or protected.is_relative_to(output):
            raise ValueError("fresh output overlaps immutable input")
    sys.path[:0] = [str(clean / "src"), str(clean)]
    from qcsd_lab.rapid_site_admission import load_admission_context, verify_site_terminal
    from qcsd_lab.rapid_rolling_readiness import validate_canary
    from qcsd_lab.rapid_rolling_capture import load_runtime
    context = load_admission_context(acquisition)
    terminal_ref = {"path": str(args.terminal.absolute()), "sha256": args.terminal_sha256}
    terminal = json.loads(checked(terminal_ref))["payload"]
    facts = verify_site_terminal(args.terminal.absolute(), context)
    if facts["outcome"] != "admitted" or not args.terminal.absolute().is_relative_to(acquisition / "attempts"):
        raise ValueError("first-site input lacks independent complete admission")
    prep_ref = {"path": str(acquisition / terminal["preparation"]["path"]), "sha256": terminal["preparation"]["sha256"]}
    preparation = json.loads(checked(prep_ref))["payload"]
    workload_ref = {"path": str(acquisition / preparation["prepared_workload"]["path"]), "sha256": preparation["prepared_workload"]["sha256"]}
    workload_raw = checked(workload_ref)
    if workload_ref["sha256"] != facts["admission"]["prepared_workload_sha256"]:
        raise ValueError("prepared graph is not the independently admitted graph")
    workload_path = Path(workload_ref["path"])
    proof_root = workload_path.parent / (workload_path.stem + "-application-response-evidence")
    proof_files = inventory(proof_root)
    if not proof_root.is_dir() or not proof_files:
        raise ValueError("complete original application-response proof is absent")
    old_plan = json.loads(read(old / "plan.json"))
    if (canonical["source"]["neqo_commit"] != old_plan["canonical_runtime"]["source"]["neqo_commit"]
        or canonical["installed_client_sha256"] != old_plan["canonical_runtime"]["installed_client_sha256"]):
        raise ValueError("first-ready runtime changed the original complete Native/client identity")
    execution, evidence = output / "execution-root", output / "evidence"
    output.mkdir(parents=True, mode=0o700)
    shutil.copytree(args.runtime_build_root / "image-context/source", execution)
    for path in execution.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode & 0o755)
    evidence.mkdir(mode=0o700)
    for name in ("inputs", "capsules", "plans"):
        (output / name).mkdir(mode=0o700)
    create(output / "canonical-runtime.json", checked(canonical_ref))
    copied = execution / "config/workloads" / workload_path.name
    create(copied, workload_raw)
    shutil.copytree(proof_root, copied.parent / proof_root.name)
    if inventory(copied.parent / proof_root.name) != proof_files:
        raise ValueError("copied complete application-response proof changed")
    old_execution, old_clean, old_build = (Path(old_plan[key]) for key in ("execution_root", "clean_runtime_root", "runtime_build_root"))
    common = {"data_root": str(data), "runtime_source_root": str(clean), "module_root": str(clean),
        "execution_root": str(execution), "workload_root": str(execution / "config/workloads"),
        "campaign_dir": str(execution / "config/campaigns"), "source_manifest": str(args.runtime_build_root.absolute() / "runtime-export/source.json"),
        "client_binary": str(args.runtime_build_root.absolute() / "runtime-export/neqo-qcsd-client"),
        "base_launcher": str(clean / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": canonical["collection_image_digest"], "execution_generation": args.name}
    original = {**common, "runtime_source_root": str(old_clean), "module_root": str(old_clean),
        "execution_root": str(old_execution), "workload_root": str(old_execution / "config/workloads"),
        "campaign_dir": str(old_execution / "config/campaigns"), "source_manifest": str(old_build / "runtime-export/source.json"),
        "client_binary": str(old_build / "runtime-export/neqo-qcsd-client"), "base_launcher": str(old_clean / "qcsd-lab"),
        "host_launcher": str(old_execution / "qcsd-lab"), "collection_image_digest": old_plan["canonical_runtime"]["collection_image_digest"],
        "execution_generation": "original-canary-011"}
    specs = {}
    for role, inputs in (("current", common), ("original", original)):
        path = output / "inputs" / f"{role}-runtime.json"
        create(path, encode({"schema_version": 1, "artifact_type": "qcsd-rapid-v6-rolling-runtime-inputs", "inputs": inputs}))
        load_runtime(path)
        specs[role] = str(path)
    refs = {}
    for mode in args.modes:
        reference = {"schema_version": 1, "plan": ref(old / "plan.json"), "deep_receipt": ref(old / f"{mode}-deep-verification.json")}
        for operation in ("capture", "deep"):
            reference[operation] = {key: ref(old / "logs" / (f"{mode}-{operation}" + suffix))
                for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"), ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
        validate_canary(reference, runtime={key: original[key] for key in (
            "runtime_source_root", "module_root", "execution_root", "source_manifest", "client_binary", "base_launcher", "host_launcher", "collection_image_digest")}, mode=mode)
        refs[mode] = reference
        create(output / "inputs" / f"{mode}-canary.json", encode(reference))
    qualification_set = args.name + "-b0001"
    named_rel = f"chaff-response-qualification-store/sets/{qualification_set}"
    qualifier_spec = execution / "config/rolling-qualification-spec.json"
    create(qualifier_spec, encode({"schema_version": 1, "qualification_sets": [{"qualification_set": qualification_set,
        "manifest": named_rel + "/_qualification-set.json", "sidecar_root": named_rel, "prefix_spec_root": None}]}))
    binding = {"schema_version": 1, "recipe": ref(Path(__file__)), "name": args.name, "output": str(output),
        "runtime_build_root": str(args.runtime_build_root.absolute()), "canonical_runtime": canonical_ref,
        "source": canonical["source"], "client_sha256": canonical["installed_client_sha256"], "collection_image_digest": canonical["collection_image_digest"],
        "execution_root": str(execution), "evidence_root": str(evidence), "runtime_specs": specs,
        "admission_root": str(acquisition), "admission_provenance": ref(acquisition / "provenance.json"), "terminal": terminal_ref,
        "preparation": prep_ref, "original_workload": workload_ref, "copied_workload": ref(copied), "application_response_files": proof_files,
        "workload_id": workload_path.stem, "qualification_set": qualification_set, "qualification_spec": ref(qualifier_spec),
        "canaries": refs, "modes": args.modes, "published_at": datetime.now(UTC).isoformat(),
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    stage_path = output / "stage.json"
    create(stage_path, encode(binding))
    prefix = [str(args.python.absolute()), "-B", str(clean / "tools/rapid_rolling_capture.py")]
    command_env = {"PYTHONPATH": str(clean / "src") + ":" + str(clean), "PYTHONDONTWRITEBYTECODE": "1"}
    commands = {}
    def command(name, argv, environment=command_env, cwd=clean):
        commands[name] = {"command": argv, "environment": environment, "cwd": str(cwd)}
    for mode in args.modes:
        command("equivalence-" + mode, prefix + ["canary-equivalence", "--canary", str(output / "inputs" / f"{mode}-canary.json"),
            "--original-runtime-spec", specs["original"], "--runtime-spec", specs["current"], "--current-inventory", str(args.runtime_build_root.absolute() / "source-inventory.json"),
            "--mode", mode, "--output", str(output / "capsules" / f"{mode}.json")])
    command("init", prefix + ["init", "--acquisition-root", str(acquisition), "--runtime-spec", specs["current"], "--evidence-root", str(evidence)])
    command("enroll", prefix + ["enroll", "--evidence-root", str(evidence), "--count", "1"])
    command("bind-readiness", [str(args.python.absolute()), "-B", str(Path(__file__).absolute()), "bind-readiness", "--stage", str(stage_path), "--stage-sha256", sha(read(stage_path))])
    docker = ["docker", "run", "--rm", "--name", "qcsd-" + args.name + "-qualify", "--network", "bridge", "--user", f"{os.getuid()}:{os.getgid()}",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--label", "org.qcsd.owner=qcsd-lab", "--label", "org.qcsd.role=rapid-v6-response-qualification",
        "--env", "QCSD_LAB_ROOT=/lab", "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json", "--env", "QCSD_LAB_IMAGE_DIGEST=" + canonical["collection_image_digest"],
        "--env", "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "PYTHONDONTWRITEBYTECODE=1", "--volume", f"{execution}:/lab:rw", "--volume", f"{output}:/operator:rw",
        "--volume", f"{Path(__file__).absolute()}:/operator-recipe.py:ro", "--workdir", "/lab", "--entrypoint", "/opt/qcsd-venv/bin/python3", canonical["collection_image_digest"],
        "-I", "-B", "/operator-recipe.py", "qualify-image", "--stage", "/operator/stage.json", "--stage-sha256", sha(read(stage_path))]
    command("qualify", docker, {}, output)
    command("plan", prefix + ["plan", "--evidence-root", str(evidence), "--enrollment", str(evidence / "batches/b0001/enrollment.json"),
        "--qualification-spec", str(qualifier_spec), "--readiness", str(output / "readiness.json"), "--output", str(output / "plans/g01.json"), "--spec-output", str(output / "plans/g01-spec.json")])
    for mode in args.modes:
        lane = f"rapid-curated-tranco50-v6-formal-b01-s01-{mode}-1200"
        command("launch-" + mode, prefix + ["launch", "--evidence-root", str(evidence), "--spec", str(output / "plans/g01-spec.json"), "--lane", lane])
    create(output / "commands.json", encode(commands))
    return {"stage": ref(stage_path), "commands": ref(output / "commands.json"), "workload": ref(copied), "scientific_credit": False}


def load_stage(args, *, image=False):
    value = json.loads(checked({"path": str(args.stage.absolute()), "sha256": args.stage_sha256}))
    if sha(read(Path(__file__))) != value["recipe"]["sha256"]:
        raise ValueError("operator recipe changed after staging")
    if not image:
        checked(value["canonical_runtime"])
        checked(value["terminal"])
        checked(value["admission_provenance"])
        checked(value["copied_workload"])
    return value


def bind_readiness(args):
    value = load_stage(args)
    current = json.loads(read(value["runtime_specs"]["current"]))["inputs"]
    sys.path[:0] = [str(Path(current["runtime_source_root"]) / "src"), current["runtime_source_root"]]
    from qcsd_lab.rapid_rolling_readiness import validate_canary
    from qcsd_lab.rapid_lane_evidence import RUNTIME_KEYS
    references = {}
    for mode, original in value["canaries"].items():
        references[mode] = {**original, "schema_version": 2, "source_equivalence": ref(Path(value["output"]) / "capsules" / f"{mode}.json")}
        validate_canary(references[mode], runtime={key: current[key] for key in RUNTIME_KEYS}, mode=mode)
    path = Path(value["output"]) / "readiness.json"
    create(path, encode(references))
    return {"readiness": ref(path), "scientific_credit": False}


def qualify_image(args):
    value = load_stage(args, image=True)
    source = json.loads(read("/usr/share/qcsd-lab/source.json"))
    client_sha = sha(read("/usr/local/bin/neqo-qcsd-client"))
    if (source != value["source"] or client_sha != value["client_sha256"]
        or os.environ.get("QCSD_LAB_IMAGE_DIGEST") != value["collection_image_digest"]):
        raise ValueError("qualification is not running in the declared matching installed image")
    from qcsd_lab.chaff_qualification import (implementation_receipt, response_only_v2_qualification_policy,
        qualify_response_chaff_v2, publish_named_qualification_set, RESPONSE_ONLY_QUALIFICATION_SCOPE, RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION)
    from qcsd_lab.runtime_provenance import validate_runtime_receipt
    canonical = json.loads(checked({"path": "/operator/canonical-runtime.json", "sha256": value["canonical_runtime"]["sha256"]}))
    if canonical["source"] != source or canonical["installed_client_sha256"] != client_sha:
        raise ValueError("copied canonical runtime differs from the installed image")
    expected = canonical["checks"]["collection"]
    if (implementation_receipt(executed_image=True)["sha256"] != expected["qualification_implementation_sha256"]
        or validate_runtime_receipt()["payload_sha256"] != expected["python_runtime_payload_sha256"]
        or response_only_v2_qualification_policy()["total_completions_per_candidate"] != 120):
        raise ValueError("installed qualification implementation or fixed120-response policy differs")
    workload = Path("/lab/config/workloads") / (value["workload_id"] + ".json")
    if sha(read(workload)) != value["original_workload"]["sha256"]:
        raise ValueError("installed qualifier was given a changed or pruned workload")
    if inventory(workload.parent / (value["workload_id"] + "-application-response-evidence")) != value["application_response_files"]:
        raise ValueError("installed qualifier's complete application-response proof changed")
    sidecars = Path("/lab/config/rolling-response-sidecars") / value["qualification_set"]
    sidecars.mkdir(parents=True, exist_ok=False)
    sets = Path("/lab/config/chaff-response-qualification-store/sets")
    sets.mkdir(parents=True, exist_ok=True)
    qualified = qualify_response_chaff_v2(value["workload_id"], qualification_root=sidecars, workload_root=workload.parent)
    named = publish_named_qualification_set([value["workload_id"]], qualification_set=value["qualification_set"],
        qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE, workload_root=workload.parent, sidecar_root=sidecars,
        publication_root=sets, qualification_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION)
    completion = {"stage_sha256": args.stage_sha256, "source": source, "client_sha256": client_sha,
        "image_digest": value["collection_image_digest"], "workload_sha256": value["original_workload"]["sha256"],
        "sidecar_sha256": qualified.sha256, "named_manifest_sha256": named.manifest_sha256,
        "qualification_set": named.qualification_set, "completed_at": datetime.now(UTC).isoformat(),
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    create(Path("/operator/qualification-complete.json"), encode(completion))
    return completion


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    item = commands.add_parser("stage")
    for name in ("runtime-build-root", "clean-runtime-root", "data-root", "output", "original-canary-root", "acquisition-root", "terminal", "python"):
        item.add_argument("--" + name, type=Path, required=True)
    for name in ("canonical-sha256", "expected-lab-commit", "terminal-sha256", "name"):
        item.add_argument("--" + name, required=True)
    item.add_argument("--modes", nargs="+", choices=("undefended", "front", "tamaraw", "buflo", "cs-buflo"), default=["undefended", "tamaraw", "cs-buflo"])
    for command in ("bind-readiness", "qualify-image"):
        item = commands.add_parser(command)
        item.add_argument("--stage", type=Path, required=True)
        item.add_argument("--stage-sha256", required=True)
    return result


if __name__ == "__main__":
    arguments = parser().parse_args()
    try:
        output = {"stage": stage, "bind-readiness": bind_readiness, "qualify-image": qualify_image}[arguments.command](arguments)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as failure:
        print(f"first-site operator: {type(failure).__name__}: {failure}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(output, indent=2, sort_keys=True, allow_nan=False))
