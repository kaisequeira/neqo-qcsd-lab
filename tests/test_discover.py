from qcsd_lab.discover import DiscoveredRequest, build_resources, exclusion_reason


def test_dependency_extraction_keeps_all_resolvable_initiators():
    requests = [
        DiscoveredRequest("https://page.test/", "Document", {}),
        DiscoveredRequest(
            "https://page.test/app.js",
            "Script",
            {},
            {"https://page.test/"},
        ),
        DiscoveredRequest(
            "https://cdn.test/image.png",
            "Image",
            {},
            {"https://page.test/", "https://page.test/app.js", "about:blank"},
        ),
    ]
    resources = build_resources(requests)
    assert resources[2]["depends_on"] == [0, 1]


def test_discovery_excludes_unsafe_and_unreviewed_requests():
    reviewed = {"https://page.test"}
    assert exclusion_reason("POST", "https://page.test/log", reviewed) == (
        "unsafe method: POST"
    )
    assert exclusion_reason("GET", "data:text/plain,hello", reviewed) == (
        "not an absolute HTTPS request"
    )
    assert exclusion_reason("GET", "https://tracker.test/code.js", reviewed) == (
        "origin not reviewed"
    )
    assert exclusion_reason("GET", "https://page.test/app.js", reviewed) is None
