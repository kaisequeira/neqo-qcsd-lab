import json
from copy import deepcopy

import pytest

from qcsd_lab.manifest import (
    EMPTY_SHA256,
    runtime_manifest,
    safe_discovery_headers,
    validate_manifest,
    validate_research_preparation,
    write_frozen_manifest,
)


def manifest(resources):
    return {
        "resources": resources,
    }


def resource(resource_id, *, dependencies=None, headers=None):
    return {
        "id": resource_id,
        "url": f"https://example.com/{resource_id}",
        "depends_on": dependencies or [],
        "headers": headers or [],
    }


def prepared_manifest():
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }
    return {
        "preparation": {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "chromium_version": "test-chromium",
            "settle_ms": 3_000,
            "observed_request_count": 2,
            "observed_origins": ["https://example.com"],
            "approved_origins": ["https://example.com"],
            "exclusions": [],
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 30,
            "stability_runs": 3,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "neqo_version": "test-neqo",
            "neqo_base_commit": "4" * 40,
            "published_qcsd_commit": "5" * 40,
            "migration_commit": "6" * 40,
            "expected_responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 100,
                    "body_sha256": "7" * 64,
                },
                {
                    "resource_id": 1,
                    "status": 200,
                    "bytes": 200,
                    "body_sha256": "8" * 64,
                },
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
        },
        "resources": [resource(0), resource(1, dependencies=[0])],
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
            "If-None-Match": '"stale-validator"',
            "Range": "bytes=0-99",
        }
    )
    assert ["accept-encoding", "gzip, br"] in headers
    assert ["referer", "https://example.com/"] in headers
    assert ["sec-fetch-mode", "cors"] in headers
    assert ["x-site-negotiation", "v2"] in headers
    assert not {"cookie", "authorization", "connection", "if-none-match", "range"} & {
        name for name, _ in headers
    }


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
        validate_manifest(manifest([resource(0, dependencies=[1]), resource(1, dependencies=[0])]))


def test_obsolete_manifest_version_marker_is_rejected():
    obsolete = manifest([resource(0)])
    obsolete["schema_version"] = 1
    with pytest.raises(ValueError, match="unsupported fields: schema_version"):
        validate_manifest(obsolete)


def test_credentialed_resource_urls_are_rejected():
    value = resource(0)
    value["url"] = "https://user:password@example.com/private"
    with pytest.raises(ValueError, match="credential-free"):
        validate_manifest(manifest([value]))


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


def test_research_preparation_accepts_the_exact_clean_policy():
    value = prepared_manifest()

    validate_research_preparation(value, workload_id="prepared-site")
    assert runtime_manifest(value) == {"resources": value["resources"]}


def test_preparation_approved_origins_are_an_allow_list():
    value = prepared_manifest()
    value["preparation"]["approved_origins"].append("https://optional.test")

    validate_manifest(value)
    validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize("location", ["source_url", "final_url"])
def test_preparation_page_origins_must_be_approved(location):
    value = prepared_manifest()
    value["preparation"][location] = "https://unapproved.test/page"

    with pytest.raises(
        ValueError, match=f"{location.removesuffix('_url').replace('_', ' ')}.*approved"
    ):
        validate_manifest(value)


def test_preparation_resource_origins_must_be_approved():
    value = prepared_manifest()
    value["resources"][0]["url"] = "https://unapproved.test/resource"

    with pytest.raises(ValueError, match="resources must use approved origins"):
        validate_manifest(value)


@pytest.mark.parametrize(
    "headers",
    [
        [["accept", "*/*"], ["accept", "text/html"]],
        [["User-Agent", "browser"], ["user-agent", "browser"]],
    ],
)
def test_research_preparation_rejects_duplicate_header_names_case_insensitively(headers):
    value = prepared_manifest()
    value["resources"][0]["headers"] = headers

    # General smoke and legacy manifests retain their existing compatibility.
    validate_manifest(value)
    with pytest.raises(ValueError, match="duplicate request header names"):
        validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize("kind", ["bare", "legacy-replay"])
def test_research_preparation_rejects_nonprepared_manifests_actionably(kind):
    value = manifest([resource(0)])
    if kind == "legacy-replay":
        value["replay"] = {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "chromium_version": "legacy",
            "settle_ms": 3_000,
            "observed_request_count": 1,
            "observed_origins": ["https://example.com"],
            "reviewed_origins": ["https://example.com"],
            "exclusions": [],
        }

    # Ordinary smoke/engineering manifest validation remains unchanged.
    validate_manifest(value)
    with pytest.raises(
        ValueError,
        match=r"research workload 'legacy'.*\./qcsd-lab prepare.*research-grade provenance",
    ):
        validate_research_preparation(value, workload_id="legacy")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("stability_runs", 2),
        ("stability_profile", "published"),
        ("stability_defense", "front"),
        ("stability_seed", 1),
        ("max_response_bytes", 1_048_575),
    ],
)
def test_research_preparation_rejects_policy_tampering(field, replacement):
    value = prepared_manifest()
    value["preparation"][field] = replacement

    validate_manifest(value)
    with pytest.raises(ValueError, match=field):
        validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize("field", ["lab_dirty", "neqo_dirty"])
def test_research_preparation_requires_clean_sources(field):
    value = prepared_manifest()
    value["preparation"]["lab_source"][field] = True

    validate_manifest(value)
    with pytest.raises(ValueError, match="clean lab and Neqo"):
        validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize("field", ["lab_patch_sha256", "neqo_patch_sha256"])
def test_research_preparation_requires_empty_patch_hashes(field):
    value = prepared_manifest()
    value["preparation"]["lab_source"][field] = "0" * 64

    validate_manifest(value)
    with pytest.raises(ValueError, match=field):
        validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize(
    "path",
    [
        ("neqo_base_commit",),
        ("published_qcsd_commit",),
        ("lab_source", "lab_commit"),
        ("lab_source", "neqo_commit"),
        ("lab_source", "neqo_pinned_commit"),
    ],
)
def test_research_preparation_requires_concrete_commit_identities(path):
    value = prepared_manifest()
    target = value["preparation"]
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = "not-a-commit"

    validate_manifest(value)
    with pytest.raises(ValueError, match="40-character lowercase hexadecimal commit"):
        validate_research_preparation(value, workload_id="prepared-site")


def test_research_preparation_permits_nonhex_redundant_migration_label():
    value = prepared_manifest()
    value["preparation"]["migration_commit"] = "unknown"

    validate_research_preparation(value, workload_id="prepared-site")


def test_research_preparation_requires_runtime_neqo_to_equal_the_pinned_commit():
    value = prepared_manifest()
    value["preparation"]["lab_source"]["neqo_pinned_commit"] = "9" * 40

    validate_manifest(value)
    with pytest.raises(ValueError, match="must equal the pinned submodule commit"):
        validate_research_preparation(value, workload_id="prepared-site")


@pytest.mark.parametrize(
    "path",
    [
        ("prepare_image_digest",),
        ("lab_source", "image_digest"),
    ],
)
def test_research_preparation_requires_concrete_image_digests(path):
    value = prepared_manifest()
    target = value["preparation"]
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = "native"

    validate_manifest(value)
    with pytest.raises(ValueError, match=r"sha256:<64 lowercase hex>"):
        validate_research_preparation(value, workload_id="prepared-site")


def test_research_preparation_binds_prepare_and_source_image_digests():
    value = prepared_manifest()
    value["preparation"]["prepare_image_digest"] = "sha256:" + "a" * 64

    validate_manifest(value)
    with pytest.raises(ValueError, match="image digest does not match"):
        validate_research_preparation(value, workload_id="prepared-site")


def test_research_preparation_retains_expected_response_coverage_gate():
    value = deepcopy(prepared_manifest())
    value["preparation"]["expected_responses"].pop()

    with pytest.raises(ValueError, match="one expected response per resource"):
        validate_research_preparation(value, workload_id="prepared-site")


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
