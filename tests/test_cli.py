import re
from pathlib import Path

import pytest

import qcsd_lab.cli as cli
from qcsd_lab.campaign import CampaignIncomplete
from qcsd_lab.cli import resolve_probe_output, response_stability_evidence


def test_public_cli_contains_only_workflow_boundaries():
    choices = set(cli.parser()._subparsers._group_actions[0].choices)
    assert choices == {"discover", "probe", "collect", "dataset", "test"}


@pytest.mark.parametrize("removed", ["doctor", "plot", "report", "export-pcap"])
def test_removed_convenience_commands_are_rejected(removed):
    with pytest.raises(SystemExit) as exit_status:
        cli.parser().parse_args([removed])
    assert exit_status.value.code == 2


def test_launcher_routes_only_retained_commands():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert "{image build|dev|discover|probe|collect|dataset|test}" in launcher
    assert 'probe|collect|dataset|test) image="${COLLECTION_IMAGE}"' in launcher
    for removed in ("doctor", "plot", "report", "export-pcap"):
        command_token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(command_token, launcher) is None


def test_incomplete_collection_exits_cleanly_with_one_result_path(monkeypatch, capsys):
    root = Path("/lab/results/20260719T061311Z")

    def incomplete(_campaign, _results, **_options):
        raise CampaignIncomplete(root)

    monkeypatch.setattr(cli, "collect_campaign", incomplete)
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["collect", "--campaign", "campaign.yml", "--capture", "direct"])
    assert exit_status.value.code == 1
    assert capsys.readouterr().err == f"campaign incomplete; results retained at {root}\n"


def test_collect_has_no_overwrite_or_ad_hoc_namespace_flags():
    collect = next(
        action
        for action in cli.parser()._subparsers._group_actions[0].choices.values()
        if action.prog.endswith(" collect")
    )
    destinations = {action.dest for action in collect._actions}
    assert destinations == {
        "help",
        "campaign",
        "capture",
        "outer_only",
        "network_condition",
        "results",
        "resume",
    }


def test_probe_retains_independently_valid_descendant_and_cleans_dependency():
    resources = [
        {"id": 0, "url": "https://page.test/", "depends_on": [], "headers": []},
        {"id": 1, "url": "https://page.test/app.js", "depends_on": [0], "headers": []},
        {"id": 2, "url": "https://cdn.test/lib.js", "depends_on": [], "headers": []},
    ]
    replay = {
        "source_url": "https://page.test/",
        "final_url": "https://page.test/",
        "chromium_version": "test",
        "settle_ms": 3000,
        "observed_request_count": 3,
        "observed_origins": ["https://page.test", "https://cdn.test"],
        "reviewed_origins": ["https://page.test", "https://cdn.test"],
        "exclusions": [],
    }
    source = {"header_policy": {}, "resources": resources, "replay": replay}
    probed = {
        "header_policy": {},
        "resources": [
            {**resource, "known_valid": resource["id"] != 0} for resource in resources
        ],
    }
    resolved = resolve_probe_output(source, probed, keep_unavailable=False)
    assert [resource["id"] for resource in resolved["resources"]] == [1, 2]
    assert resolved["resources"][0]["depends_on"] == []
    assert resolved["replay"]["exclusions"] == [
        {"url": "https://page.test/", "reason": "HTTP/3 preflight unavailable"}
    ]


def test_response_stability_evidence_identifies_dynamic_and_partial_resources():
    def run(first_hash, second_hash, *, complete=True):
        return {
            "completion_status": "complete" if complete else "partial",
            "responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 10,
                    "body_sha256": first_hash,
                    "outcome": "succeeded",
                    "complete": True,
                },
                {
                    "resource_id": 1,
                    "status": 200,
                    "bytes": 20,
                    "body_sha256": second_hash,
                    "outcome": "succeeded",
                    "complete": True,
                },
            ],
        }

    evidence = response_stability_evidence(
        [run("stable", "first"), run("stable", "second"), run("stable", "third")]
    )
    assert evidence == {"runs": 3, "stable_resource_ids": [0]}

    partial = response_stability_evidence([run("x", "y"), run("x", "y", complete=False)])
    assert partial == {"runs": 2, "stable_resource_ids": []}
