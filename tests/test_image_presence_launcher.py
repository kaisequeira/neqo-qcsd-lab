"""Keep image absence separate from bounded Docker metadata failures."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


LAUNCHER = Path(__file__).parents[1] / "qcsd-lab"
IMAGE = "sha256:" + "8" * 64


@pytest.mark.parametrize(
    ("mode", "success", "bounds", "message"),
    (
        ("present", True, ("10",), ""),
        ("empty-then-present", True, ("10", "30"), "retrying once with a 30s bound"),
        ("wrapper-timeout-then-present", True, ("10", "30"), "status=124 bound_s=10"),
        ("missing", False, ("10",), "Missing image"),
        ("always-empty", False, ("10", "30"), "no result at the 30s Docker API boundary"),
        ("wrapper-always-timeout", False, ("10", "30"), "status=124 bound_s=unreported"),
        ("timeout-with-error", False, ("10",), "service returned an unrelated error"),
        ("identity-error", False, ("10",), "pinned daemon identity changed"),
        ("unexpected-error", False, ("10",), "Cannot connect to Docker"),
        ("wrong-id", False, ("10",), "different immutable ID"),
    ),
)
def test_image_presence_uses_bounded_read_only_metadata_and_retains_failure_kind(
    tmp_path: Path,
    mode: str,
    success: bool,
    bounds: tuple[str, ...],
    message: str,
) -> None:
    launcher = LAUNCHER.read_text(encoding="utf-8")
    start = launcher.index("_qcsd_require_image_present() {")
    function = launcher[start : launcher.index("\n}\n", start) + 2]
    calls = tmp_path / "calls"
    shell = f"""
set -euo pipefail
_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10
_qcsd_docker_api_with_timeout() {{
  local duration="$1" count
  shift
  [[ "$*" == "image inspect --format {{{{.Id}}}} $QCSD_REQUESTED" ]] || return 99
  printf '%s\\n' "$duration" >> "$QCSD_CALLS"
  count="$(wc -l < "$QCSD_CALLS")"
  case "$QCSD_MODE" in
    present) printf '%s\\n' "$QCSD_REQUESTED" ;;
    empty-then-present)
      if (( count == 1 )); then return 124; fi
      printf '%s\\n' "$QCSD_REQUESTED"
      ;;
    wrapper-timeout-then-present)
      if (( count == 1 )); then
        printf 'qcsd-api-failure phase=unspecified action=image-inspect status=124 bound_s=%s\\n' "$duration" >&2
        return 124
      fi
      printf '%s\\n' "$QCSD_REQUESTED"
      ;;
    missing)
      printf 'Error: No such image: %s\\n' "$QCSD_REQUESTED" >&2
      printf 'qcsd-api-failure phase=unspecified action=image-inspect status=1 bound_s=%s\\n' "$duration" >&2
      return 1
      ;;
    always-empty) return 124 ;;
    wrapper-always-timeout)
      if (( count == 1 )); then local bound="$duration"; else local bound=unreported; fi
      printf 'qcsd-api-failure phase=unspecified action=image-inspect status=124 bound_s=%s\\n' "$bound" >&2
      return 124
      ;;
    timeout-with-error)
      printf '%s\\n' 'service returned an unrelated error' >&2
      printf 'qcsd-api-failure phase=unspecified action=image-inspect status=124 bound_s=%s\\n' "$duration" >&2
      return 124
      ;;
    identity-error)
      printf '%s\\n' 'Docker pinned daemon identity changed' >&2
      return 125
      ;;
    unexpected-error)
      printf '%s\\n' 'Cannot connect to Docker' >&2
      return 1
      ;;
    wrong-id) printf 'sha256:%064d\\n' 2 ;;
    *) return 99 ;;
  esac
}}
{function}
_qcsd_require_image_present "$QCSD_REQUESTED"
[[ "$_QCSD_INSPECTED_IMAGE_ID" == "$QCSD_REQUESTED" ]]
"""
    result = subprocess.run(
        ["bash", "-c", shell],
        env={**os.environ, "QCSD_CALLS": str(calls), "QCSD_MODE": mode,
             "QCSD_REQUESTED": IMAGE},
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is success, result.stderr
    assert tuple(calls.read_text(encoding="utf-8").splitlines()) == bounds
    assert message in result.stderr
    if mode != "missing":
        assert "Missing image" not in result.stderr
    assert result.stdout == ""


def test_collection_and_qualification_prepare_use_the_same_presence_fence() -> None:
    launcher = LAUNCHER.read_text(encoding="utf-8")
    assert 'if ! _qcsd_require_image_present "${image}"; then' in launcher
    assert 'if ! _qcsd_require_image_present "${PREPARE_IMAGE}"; then' in launcher
    assert 'if ! _qcsd_docker_api image inspect' not in launcher
    assert 'image_id="$(_qcsd_docker_api image inspect' not in launcher
    assert 'image_id="${_QCSD_INSPECTED_IMAGE_ID}"' in launcher
