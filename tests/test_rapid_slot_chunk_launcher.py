"""Execute the actual host selector and installed inline contract, without Docker."""
from pathlib import Path
from types import SimpleNamespace
import ast
import os
import subprocess

import pytest

from qcsd_lab import rapid_slot_chunks as chunks

ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / "qcsd-lab").read_text()


def selector(tmp_path, name, *, action="run", authority="bound-intent", symlink=False):
    campaign = tmp_path / (name + ".yml")
    if symlink:
        target = tmp_path / "target.yml"
        target.write_text("retained full campaign\n")
        campaign.symlink_to(target)
    else:
        campaign.write_text("retained full campaign\n")
    begin = SHELL.index("rapid_v2_diagnostic_pattern=")
    end = SHELL.index('elif [[ "${1:-}" == "resume" &&', begin)
    program = ('set -e\nROOT="$QCSD_LAUNCH_TEST_ROOT"\nstudy_campaign_name="${2##*/}"\n'
               'rapid_capture=0\nrapid_capture_version=\nrapid_capture_mode=\nrapid_capture_role=\n'
               + SHELL[begin:end] + 'fi\n'
               + 'printf "%s|%s|%s|%s\\n" "$rapid_capture" "$rapid_capture_version" '
                 '"$rapid_capture_role" "$rapid_capture_mode"\n')
    return subprocess.run(["bash", "-c", program, "selector", action, str(campaign)],
                          env={**os.environ, "QCSD_RAPID_ROLLING_LAUNCH_INPUT": authority,
                               "QCSD_LAUNCH_TEST_ROOT": str(tmp_path)},
                          text=True, capture_output=True, check=False)


def inline():
    start = SHELL.index("import re\nimport sys\nfrom pathlib import Path\nfrom qcsd_lab.experiment import (")
    end = SHELL.index('\n\' "${1}" "${rapid_capture_target}"', start)
    tree = ast.parse(SHELL[start:end])
    return next(node for node in tree.body if isinstance(node, ast.If)
                and ast.unparse(node.test) == "role == 'formal'")


def campaign(mode="tamaraw", *, start=0, count=16, generation=1):
    suffix = "" if generation == 1 else f"-g{generation:02d}"
    return SimpleNamespace(
        name=f"rapid-selected50-slot-v1-p{'a' * 16}-s03-{mode}-v{start:02d}-n{count:02d}-c01{suffix}",
        schema_version=1, purpose="evaluation", profile="research-1200", request_policies=("as-defined",),
        workloads=tuple(SimpleNamespace(id=f"complete{i}", visits=count,
                                      qualification_set_manifest_sha256="b" * 64) for i in range(2)),
        defenses=(SimpleNamespace(name=mode),), chaff_qualification_set=None if mode == "undefended" else "complete-cohort",
    )


def installed(value, *, mode="tamaraw", action="run", version="v6"):
    tree = ast.fix_missing_locations(ast.Module(body=[inline()], type_ignores=[]))
    exec(compile(tree, "actual-installed-inline-contract", "exec"),
         {"campaign": value, "expected_mode": mode, "action": action, "study_version": version, "role": "formal"})


@pytest.mark.parametrize("mode", ["undefended", "front", "tamaraw", "buflo", "cs-buflo"])
def test_actual_selector_and_installed_guard_keep_all_five_modes(tmp_path, mode):
    value = campaign(mode)
    selected = selector(tmp_path, value.name)
    assert selected.returncode == 0 and selected.stdout.strip() == f"1|v6|formal|{mode}"
    installed(value, mode=mode)
    pattern = SHELL.split("rapid_slot_chunk_pattern='", 1)[1].split("'", 1)[0]
    assert pattern == chunks.LAUNCH_NAME_PATTERN


def test_actual_selector_requires_rolling_authority_and_regular_campaign(tmp_path):
    name = campaign().name
    assert selector(tmp_path, name, authority="").returncode == 1
    child = tmp_path / "linked"
    child.mkdir()
    assert selector(child, name, symlink=True).returncode == 1


def test_exact_namespace_refuses_unknown_mode_and_numeric_aliases(tmp_path):
    for suffix in ["unknown-v00-n16-c01", "tamaraw-v64-n16-c01", "tamaraw-v00-n17-c01",
                   "tamaraw-v00-n00-c01", "tamaraw-v00-n16-c65", "tamaraw-v00-n16-c01-g01"]:
        name = f"rapid-selected50-slot-v1-p{'a' * 16}-s03-" + suffix
        assert selector(tmp_path, name).stdout.strip() == "0|||"
    for name in [campaign().name.replace("s03", "s51"), campaign().name.replace("p" + "a" * 16, "p" + "g" * 16)]:
        assert selector(tmp_path, name).stdout.strip() == "0|||"


def test_installed_guard_refuses_end_overflow_changed_visit_count_and_duplicate_workloads():
    value = campaign(start=60, count=16)
    with pytest.raises(ValueError):
        installed(value)
    value = campaign()
    value.workloads[0].visits = 4
    with pytest.raises(ValueError):
        installed(value)
    value = campaign()
    value.workloads[1].id = value.workloads[0].id
    with pytest.raises(ValueError):
        installed(value)


def test_tail_and_immediate_recovery_keep_registered_short_count(tmp_path):
    value = campaign(start=52, count=12, generation=2)
    assert selector(tmp_path, value.name).stdout.strip() == "1|v6|formal|tamaraw"
    installed(value)
    for start, count in [(63, 1), (0, 8), (32, 16)]:
        installed(campaign(start=start, count=count))


def test_chunk_generic_resume_stays_refused_and_old_four_visit_branch_stays_exact(tmp_path):
    assert selector(tmp_path, campaign().name, action="resume").stdout.strip() == "0|||"
    with pytest.raises(SystemExit):
        installed(campaign(), action="resume")
    with pytest.raises(SystemExit):
        installed(campaign(), version="v5")
    old = campaign(count=4)
    old.name = "rapid-curated-tranco50-v6-formal-b01-s03-tamaraw-1200"
    assert selector(tmp_path, old.name).stdout.strip() == "1|v6|formal|tamaraw"
    installed(old)
    old.workloads[0].visits = 16
    with pytest.raises(SystemExit):
        installed(old)


def test_installed_guard_keeps_profile_requests_defense_and_named_manifest_contracts():
    for key, changed in [("purpose", "smoke"), ("profile", "unknown"),
                         ("request_policies", ("serialized",)), ("workloads", ()),
                         ("defenses", (SimpleNamespace(name="front"),)), ("chaff_qualification_set", None)]:
        value = campaign()
        setattr(value, key, changed)
        with pytest.raises(ValueError):
            installed(value)
    value = campaign()
    value.workloads[0].qualification_set_manifest_sha256 = None
    with pytest.raises(SystemExit):
        installed(value)


def test_host_selector_uses_unchanged_v6_downstream_authority_gate():
    assert 'if [[ "${rapid_capture_version}" == "v6" ]]; then\n      rapid_epoch_input="${QCSD_RAPID_ROLLING_LAUNCH_INPUT:-}"' in SHELL
    assert "slot chunks require explicit hash-bound rolling policy and lane authority" in SHELL
    # Resume selector remains the original enum and cannot select the new layout.
    resume = SHELL.split('elif [[ "${1:-}" == "resume" &&', 1)[1].split("then", 1)[0]
    assert "rapid_slot_chunk_pattern" not in resume
