#!/usr/bin/env python3
"""Emit an authenticated, read-only installed witness check before flight staging.

This command performs HOST validation and prints a Docker argv; it never
starts Docker. Root records and runs that argv on the actual consumer image.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import qualification_delivery_compatibility as compatibility
from qcsd_lab.rapid_operation_facts import OperationFacts

IMAGE_PROGRAM = '''import json,os,sys
from qcsd_lab import qualification_delivery_compatibility as c
from qcsd_lab.rapid_operation_facts import OperationFacts
reference={"path":sys.argv[1],"sha256":sys.argv[2]}
context=OperationFacts()
with context.scope():
 value,_,_=c.validate(reference,body_policy=sys.argv[3],actual_image=os.environ["QCSD_LAB_IMAGE_DIGEST"])
 context.check()
print(json.dumps({"installed_witness_verified":True,"workload_count":len(value["workloads"]),"consumer_source":value["consumer_source"],"consumer_image":value["consumer_image"],"scientific_credit":False,"formal_credit_added":0},sort_keys=True))
'''


def image_command(reference, image, roots, name):
    if not isinstance(name, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", name) is None:
        raise ValueError("installed input check needs an explicit safe container name")
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("installed input check needs its actual consumer image digest")
    argv = ["docker", "run", "--rm", "--name", name, "--read-only", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "QCSD_LAB_IMAGE_DIGEST=" + image]
    selected = sorted(set(Path(root).absolute() for root in roots))
    for root in selected:
        if not root.is_absolute() or ".." in root.parts or any(char in str(root) for char in (",", "\n", "\r", "\0")):
            raise ValueError("installed input check requires canonical same-absolute RO roots")
        argv += ["--mount", f"type=bind,src={root},dst={root},readonly"]
    if not any(Path(reference["path"]).is_relative_to(root) for root in selected):
        raise ValueError("installed input check does not transport its exact witness")
    return argv + ["--entrypoint", "/opt/qcsd-venv/bin/python3", image,
                   "-I", "-B", "-c", IMAGE_PROGRAM, reference["path"], reference["sha256"], compatibility.POLICY]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness", type=Path, required=True)
    parser.add_argument("--witness-sha256", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    reference = {"path": str(args.witness.absolute()), "sha256": args.witness_sha256}
    context = OperationFacts()
    with context.scope():
        value, _, _ = compatibility.validate(reference, body_policy=compatibility.POLICY)
        roots = compatibility.roots(reference, body_policy=compatibility.POLICY)
        command = image_command(reference, value["consumer_image"], roots, args.name)
        context.check()
    print(json.dumps({"command": command, "witness": reference,
                      "consumer_canonical": value["consumer"]["canonical"],
                      "consumer_source": value["consumer_source"], "consumer_image": value["consumer_image"],
                      "workload_count": len(value["workloads"]),
                      "docker_executed": False, "scientific_credit": False, "formal_credit_added": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
