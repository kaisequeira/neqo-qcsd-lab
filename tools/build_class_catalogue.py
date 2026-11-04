#!/usr/bin/env python3
"""Build pinned Tranco and 600-candidate receipts without network access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qcsd_lab.class_catalogue import (
    build_candidate_catalogue_receipt,
    build_tranco_snapshot_receipt,
    parse_tranco_csv,
    write_candidate_catalogue_receipt,
    write_tranco_snapshot_receipt,
)
from qcsd_lab.class_study import STUDY_ID
from qcsd_lab.util import sha256_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--list-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--retrieved-at", required=True)
    arguments = parser.parse_args()

    if not arguments.destination.is_dir() or arguments.destination.is_symlink():
        raise SystemExit("destination must be an existing regular directory")
    snapshot = parse_tranco_csv(
        arguments.csv.read_bytes(),
        list_id=arguments.list_id,
        expected_sha256=arguments.expected_sha256,
        source_url=arguments.source_url,
        retrieved_at=arguments.retrieved_at,
    )
    tranco_path = arguments.destination / f"tranco-{arguments.list_id}.receipt.json"
    candidate_path = arguments.destination / f"{STUDY_ID}-candidates.json"
    write_tranco_snapshot_receipt(tranco_path, build_tranco_snapshot_receipt(snapshot))
    write_candidate_catalogue_receipt(
        candidate_path,
        build_candidate_catalogue_receipt(snapshot),
    )
    print(
        json.dumps(
            {
                str(path): sha256_file(path)
                for path in (tranco_path, candidate_path)
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
