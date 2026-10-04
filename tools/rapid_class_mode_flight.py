#!/usr/bin/env python3
"""Stage and run one full-graph flight for an enrolled group and defense mode."""
from pathlib import Path
import runpy


def main():
    recipe = Path(__file__).resolve().parent / "_rapid_class_mode_flight/flight/operator.py"
    runpy.run_path(str(recipe), run_name="__main__")


if __name__ == "__main__":
    main()
