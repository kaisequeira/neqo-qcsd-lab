#!/usr/bin/env python3
"""Create a domain-source receipt from an external CrUX resource-URL JSON file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qcsd_lab.class_curated_source import import_curated_source


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import curated domains and URL-origin hints as a create-only, "
            "hash-bound source receipt. "
            "This does not select a study cohort or authorize acquisition."
        )
    )
    parser.add_argument(
        "source", type=Path, help="untrusted CrUX domain/resource-URL JSON file"
    )
    parser.add_argument("destination", type=Path, help="new receipt JSON path (must not exist)")
    arguments = parser.parse_args()
    try:
        result = import_curated_source(arguments.source, arguments.destination)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
