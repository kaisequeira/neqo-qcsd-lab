"""Command guards only; no Docker or witness authority is simulated."""
from importlib import util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("delivery_input_check", ROOT / "tools/rapid_delivery_input_check.py")
check = util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_installed_check_is_same_absolute_readonly_and_offline(tmp_path):
    reference = {"path": str(tmp_path / "witness.json"), "sha256": "b" * 64}
    image = "sha256:" + "a" * 64
    command = check.image_command(reference, image, [tmp_path], "fresh-input-check")
    assert command[:3] == ["docker", "run", "--rm"]
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
    assert mounts == [f"type=bind,src={tmp_path},dst={tmp_path},readonly"]
    assert command[-4:] == [check.IMAGE_PROGRAM, reference["path"], reference["sha256"], check.compatibility.POLICY]
    assert command[command.index("--entrypoint") + 2] == image


@pytest.mark.parametrize("mutation", ["name", "image", "missing-witness"])
def test_unsafe_or_uncovered_installed_command_refuses(tmp_path, mutation):
    reference = {"path": str(tmp_path / "witness.json"), "sha256": "b" * 64}
    image, name, roots = "sha256:" + "a" * 64, "fresh-input-check", [tmp_path]
    if mutation == "name":
        name = "unsafe container name"
    elif mutation == "image":
        image = "mutable:latest"
    else:
        roots = [tmp_path / "other"]
    with pytest.raises(ValueError):
        check.image_command(reference, image, roots, name)
