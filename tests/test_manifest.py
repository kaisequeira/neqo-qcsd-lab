import json

import pytest

from qcsd_lab.manifest import safe_discovery_headers, validate_manifest, write_frozen_manifest


def manifest(resources):
    return {
        "schema_version": 2,
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


def test_frozen_manifest_requires_new_version_for_changes(tmp_path):
    path = tmp_path / "workload.json"
    first = manifest([resource(0)])
    digest = write_frozen_manifest(path, first)
    assert digest in path.with_suffix(".json.sha256").read_text()
    write_frozen_manifest(path, json.loads(path.read_text()))
    with pytest.raises(FileExistsError):
        write_frozen_manifest(path, manifest([resource(0), resource(1)]))
