"""Execute Dockerfile permission transport on a controlled installed package.

No Docker, network, image authority or scientific trace credit is exercised.
Every actual package source role is copied, including the six strict readers.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
STAGES = ("lab-runtime", "collection", "prepare")


def _stage(name: str) -> str:
    source = (ROOT / "Dockerfile").read_text()
    stages = list(re.finditer(r"^FROM .+ AS (\S+)$", source, flags=re.MULTILINE))
    index = next(index for index, match in enumerate(stages) if match.group(1) == name)
    end = stages[index + 1].start() if index + 1 < len(stages) else len(source)
    return source[stages[index].start():end]


def _command(name: str) -> str:
    commands = re.findall(r"^\s*python3 -c '([^'\n]+)' && \\", _stage(name), flags=re.MULTILINE)
    normalization = [code for code in commands if "import qcsd_lab;" in code and ".chmod(" in code]
    assert len(normalization) == 1
    return normalization[0]


def _run(code: str, wheel: Path) -> subprocess.CompletedProcess[str]:
    # The process imports the controlled wheel from its only PYTHONPATH entry.
    # Its cwd excludes the real repository and bytecode writes stay disabled.
    environment = {**os.environ, "PYTHONPATH": str(wheel), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-B", "-c", code], cwd=wheel,
                          env=environment, text=True, capture_output=True, timeout=20, check=False)


@pytest.fixture
def installed(tmp_path: Path):
    wheel = tmp_path / "wheel"
    package = wheel / "qcsd_lab"
    source = ROOT / "src/qcsd_lab"
    modules = {}
    for original in sorted(source.rglob("*.py")):
        path = package / original.relative_to(source)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = original.read_bytes()
        path.write_bytes(raw)
        path.chmod(0o664)
        modules[path] = raw
    # Cover recursive package files as well as the current flat module set.
    nested = package / "nested/reader.py"
    nested.parent.mkdir()
    nested.write_bytes(b"# controlled nested wheel module\n")
    nested.chmod(0o664)
    modules[nested] = nested.read_bytes()
    protected = {}
    for relative, mode in (("qcsd_lab/command.py", 0o755),
                           ("qcsd_lab/resource.json", 0o664),
                           ("other_package/reader.py", 0o664),
                           ("native/client", 0o755)):
        path = wheel / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unchanged unrelated or executable role\n")
        path.chmod(mode)
        protected[path] = (path.read_bytes(), mode)
    link = package / "linked.py"
    link.symlink_to(wheel / "other_package/reader.py")
    return wheel, package, modules, protected, link


def test_each_project_install_is_normalized_before_runtime_provenance():
    source = (ROOT / "Dockerfile").read_text()
    assert source.count("uv sync ") == len(STAGES)
    for name in STAGES:
        text = _stage(name)
        command = _command(name)
        install = re.search(r"uv sync [\s\S]*?&&", text)
        assert install is not None
        normalize = text.index("python3 -c '" + command + "'")
        receipt = text.index("python3 -m qcsd_lab.runtime_provenance ")
        assert install.end() < normalize < receipt


@pytest.mark.parametrize("stage", STAGES)
def test_real_normalization_covers_all_modules_and_preserves_other_roles(installed, stage: str):
    wheel, package, modules, protected, link = installed
    # The installed 0664 transport reproduces the actual strict-guard refusal.
    guard = "from qcsd_lab import rapid_fixed_condition_target as fixed; fixed._acquisition_reader_sources()"
    before = _run(guard, wheel)
    assert before.returncode != 0
    assert "outside the exact prospective Source set" in before.stderr
    result = _run(_command(stage), wheel)
    assert result.returncode == 0, result.stderr
    for path, raw in modules.items():
        assert path.read_bytes() == raw
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
    for path, (raw, mode) in protected.items():
        assert path.read_bytes() == raw
        assert stat.S_IMODE(path.stat().st_mode) == mode
    assert link.is_symlink()
    assert set(package.rglob("*.py")) == set(modules) | {package / "command.py", link}
    after = _run(guard, wheel)
    assert after.returncode == 0, after.stderr


def test_normalized_installed_reader_still_refuses_mid_action_mode_mutation(installed):
    wheel, _, _, _, _ = installed
    result = _run(_command("collection"), wheel)
    assert result.returncode == 0, result.stderr
    result = _run("""
from pathlib import Path
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab.rapid_operation_facts import OperationFacts
context = OperationFacts()
with context.scope():
    readers = fixed._acquisition_reader_sources()
    path = Path(readers['src/qcsd_lab/rapid_supplemental_cohort.py']['path'])
    assert path.stat().st_mode & 0o7777 == 0o644
    path.chmod(0o664)
    try:
        context.check()
    except ValueError as error:
        assert 'operation dependency' in str(error)
    else:
        raise AssertionError('installed full-mode mutation escaped the action fence')
""", wheel)
    assert result.returncode == 0, result.stderr
