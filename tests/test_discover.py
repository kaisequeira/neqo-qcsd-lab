import sys
from types import ModuleType

from qcsd_lab.discover import (
    DiscoveredRequest,
    _RequestAdmission,
    build_resources,
    discover_page,
    exclusion_reason,
    merge_request_headers,
)


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
    reviewed = {"https://cdn.test", "https://page.test"}
    assert exclusion_reason("POST", "https://page.test/log", reviewed) == ("unsafe method: POST")
    assert exclusion_reason("GET", "data:text/plain,hello", reviewed) == (
        "not an absolute HTTPS request"
    )
    assert exclusion_reason("GET", "https://tracker.test/code.js", reviewed) == (
        "origin not approved"
    )
    assert exclusion_reason("GET", "https://page.test/app.js", reviewed) is None
    assert exclusion_reason("GET", "https://cdn.test/app.js", reviewed) is None


def test_request_stage_admission_continues_multi_origin_gets_and_blocks_tracker_and_post():
    class Session:
        def __init__(self) -> None:
            self.commands: list[tuple[str, dict[str, str]]] = []

        def send(self, command: str, parameters: dict[str, str]) -> None:
            self.commands.append((command, parameters))

    session = Session()
    admission = _RequestAdmission({"https://cdn.test", "https://page.test"})
    requests = [
        ("page", "GET", "https://page.test/"),
        ("cdn", "GET", "https://cdn.test/app.js"),
        ("tracker", "GET", "https://tracker.test/beacon.js"),
        ("post", "POST", "https://page.test/cdn-cgi/rum"),
    ]

    for request_id, method, url in requests:
        admission.enforce(
            session,
            {
                "requestId": request_id,
                "request": {"method": method, "url": url},
            },
        )

    assert session.commands == [
        ("Fetch.continueRequest", {"requestId": "page"}),
        ("Fetch.continueRequest", {"requestId": "cdn"}),
        (
            "Fetch.failRequest",
            {"requestId": "tracker", "errorReason": "BlockedByClient"},
        ),
        (
            "Fetch.failRequest",
            {"requestId": "post", "errorReason": "BlockedByClient"},
        ),
    ]
    assert admission.observed_request_count == 4
    assert admission.observed_origins == {
        "https://cdn.test",
        "https://page.test",
        "https://tracker.test",
    }
    assert sorted(admission.exclusions.values(), key=lambda item: item["url"]) == [
        {
            "url": "https://page.test/cdn-cgi/rum",
            "reason": "unsafe method: POST",
        },
        {
            "url": "https://tracker.test/beacon.js",
            "reason": "origin not approved",
        },
    ]


def test_discover_page_installs_request_stage_policy_before_navigation(monkeypatch):
    events = [
        {
            "requestId": "page",
            "request": {"method": "GET", "url": "https://page.test/", "headers": {}},
            "type": "Document",
            "documentURL": "https://page.test/",
        },
        {
            "requestId": "cdn",
            "request": {
                "method": "GET",
                "url": "https://cdn.test/app.js",
                "headers": {"Accept": "*/*"},
            },
            "type": "Script",
            "documentURL": "https://page.test/",
        },
        {
            "requestId": "tracker",
            "request": {
                "method": "GET",
                "url": "https://tracker.test/beacon.js",
                "headers": {},
            },
            "type": "Script",
            "documentURL": "https://page.test/",
        },
        {
            "requestId": "post",
            "request": {
                "method": "POST",
                "url": "https://page.test/cdn-cgi/rum",
                "headers": {},
            },
            "type": "Fetch",
            "documentURL": "https://page.test/",
        },
    ]

    class Session:
        def __init__(self) -> None:
            self.handlers = {}
            self.commands = []
            self.paused = {event["requestId"]: event for event in events}

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def send(self, command: str, parameters=None) -> None:
            self.commands.append((command, parameters))
            if command == "Fetch.continueRequest":
                network_event = self.paused[parameters["requestId"]]
                self.handlers["Network.requestWillBeSent"](network_event)

    class Page:
        url = "https://page.test/"

        def __init__(self, session: Session) -> None:
            self.session = session

        def goto(self, url: str, *, wait_until: str, timeout: int) -> None:
            assert url == self.url
            assert wait_until == "load"
            assert timeout == 1_000
            for event in events:
                self.session.handlers["Fetch.requestPaused"](event)

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 3_000

        def close(self) -> None:
            return None

    class Context:
        def __init__(self) -> None:
            self.session = Session()
            self.page = Page(self.session)

        def new_page(self) -> Page:
            return self.page

        def new_cdp_session(self, page: Page) -> Session:
            assert page is self.page
            return self.session

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.context = Context()
            self.context_options = None

        def new_context(self, **options) -> Context:
            self.context_options = options
            return self.context

        def close(self) -> None:
            return None

    browser = Browser()

    class Chromium:
        def launch(self, **_options) -> Browser:
            return browser

    class Playwright:
        chromium = Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    sync_api = ModuleType("playwright.sync_api")
    sync_api.sync_playwright = Playwright  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    result = discover_page(
        "https://page.test/",
        allow_origins=["https://page.test", "https://cdn.test"],
        timeout_ms=1_000,
    )

    assert browser.context_options == {
        "ignore_https_errors": False,
        "service_workers": "block",
    }
    assert (
        "Fetch.enable",
        {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
    ) in browser.context.session.commands
    assert [resource["url"] for resource in result.resources] == [
        "https://page.test/",
        "https://cdn.test/app.js",
    ]
    assert result.resources[1]["depends_on"] == [0]
    assert result.observed_request_count == 4
    assert result.exclusions == [
        {
            "url": "https://page.test/cdn-cgi/rum",
            "reason": "unsafe method: POST",
        },
        {
            "url": "https://tracker.test/beacon.js",
            "reason": "origin not approved",
        },
    ]


def test_cdp_header_merge_is_case_insensitive_and_extra_info_wins():
    headers: dict[str, str] = {}

    merge_request_headers(
        headers,
        {"User-Agent": "request-will-be-sent", "ACCEPT": "*/*"},
    )
    merge_request_headers(
        headers,
        {"user-agent": "extra-info", "Accept": "text/html"},
    )

    assert headers == {"user-agent": "extra-info", "accept": "text/html"}
