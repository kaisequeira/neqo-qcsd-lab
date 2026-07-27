import json

import pytest

from qcsd_lab.manifest import (
    runtime_manifest,
    safe_discovery_headers,
    validate_manifest,
    write_frozen_manifest,
)


def manifest(resources):
    return {
        "header_policy": {"mode": "fresh-browser"},
        "resources": resources,
    }


def resource(resource_id, *, dependencies=None, headers=None):
    return {
        "id": resource_id,
        "url": f"https://example.com/{resource_id}",
        "depends_on": dependencies or [],
        "headers": headers or [],
    }


def test_safe_discovery_headers_preserve_behavior_but_remove_secrets():
    headers = safe_discovery_headers(
        {
            "Accept-Encoding": "gzip, br",
            "Referer": "https://example.com/",
            "Sec-Fetch-Mode": "cors",
            "X-Site-Negotiation": "v2",
            "Cookie": "secret",
            "Authorization": "secret",
            "Connection": "keep-alive",
        }
    )
    assert ["accept-encoding", "gzip, br"] in headers
    assert ["referer", "https://example.com/"] in headers
    assert ["sec-fetch-mode", "cors"] in headers
    assert ["x-site-negotiation", "v2"] in headers
    assert not {"cookie", "authorization", "connection"} & {name for name, _ in headers}


@pytest.mark.parametrize("name", ["cookie", "authorization", "connection", ":authority"])
def test_stored_unsafe_headers_are_rejected(name):
    with pytest.raises(ValueError):
        validate_manifest(manifest([resource(0, headers=[[name, "value"]])]))


def test_unknown_self_and_cyclic_dependencies_are_rejected():
    with pytest.raises(ValueError):
        validate_manifest(manifest([resource(0, dependencies=[9])]))
    with pytest.raises(ValueError):
        validate_manifest(manifest([resource(0, dependencies=[0])]))
    with pytest.raises(ValueError, match="cycle"):
        validate_manifest(
            manifest([resource(0, dependencies=[1]), resource(1, dependencies=[0])])
        )


def test_obsolete_manifest_version_marker_is_rejected():
    obsolete = manifest([resource(0)])
    obsolete["schema_version"] = 1
    with pytest.raises(ValueError, match="unsupported fields: schema_version"):
        validate_manifest(obsolete)


def test_replay_metadata_is_validated_and_removed_from_runtime_manifest():
    value = manifest([resource(0)])
    value["replay"] = {
        "source_url": "https://example.com/",
        "final_url": "https://example.com/",
        "chromium_version": "test",
        "settle_ms": 3000,
        "observed_request_count": 1,
        "observed_origins": ["https://example.com"],
        "reviewed_origins": ["https://example.com"],
        "exclusions": [],
        "response_stability": {"runs": 3, "stable_resource_ids": [0]},
    }
    validate_manifest(value)
    assert "replay" not in runtime_manifest(value)
    value["replay"]["reviewed_origins"] = ["https://unobserved.test"]
    with pytest.raises(ValueError, match="subset"):
        validate_manifest(value)


def test_replay_response_stability_requires_repeated_unique_resource_ids():
    value = manifest([resource(0)])
    value["replay"] = {
        "source_url": "https://example.com/",
        "final_url": "https://example.com/",
        "chromium_version": "test",
        "settle_ms": 3000,
        "observed_request_count": 1,
        "observed_origins": ["https://example.com"],
        "reviewed_origins": ["https://example.com"],
        "exclusions": [],
        "response_stability": {"runs": 1, "stable_resource_ids": [0]},
    }
    with pytest.raises(ValueError, match="response_stability is invalid"):
        validate_manifest(value)


def test_frozen_manifest_requires_new_version_for_changes(tmp_path):
    path = tmp_path / "workload.json"
    first = manifest([resource(0)])
    digest = write_frozen_manifest(path, first)
    assert len(digest) == 64
    assert "schema_version" not in json.loads(path.read_text())
    assert not path.with_suffix(".json.sha256").exists()
    write_frozen_manifest(path, json.loads(path.read_text()))
    with pytest.raises(FileExistsError):
        write_frozen_manifest(path, manifest([resource(0), resource(1)]))
