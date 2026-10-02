# Why the supplied domains are only part of the 50-site study

The supplied `url-resource-urls 1.json` is a useful **candidate list**, not a
list of 50 capture-ready websites. Its exact
[repository copy](../config/curated-sources/crux-73-v1.raw.json) contains **73
distinct site names**. The listed resource URLs describe earlier observations;
they do not show that those resources still load, that the current page uses
HTTP/3, or that it loads resources from another origin. I could not reproduce
the earlier claim of **58 unique classes** from a documented rule: the file has
73 distinct site names, 63 with at least one listed resource, and 57 with a
listed resource and no automatic safety flag.

On **2 October 2026**, each supplied site's homepage received a short HTTP/3
screen using the same Neqo client intended for collection. Working control
sites passed before and after each batch. This was a quick diagnostic, **not
formal acquisition** or proof that a whole page can be captured.
The same ordered screen was repeated after the historical rapid v4 rules were frozen;
the [independently checked retest](CURATED-H3-SCREEN-2026-10-02.md#post-freeze-v4-screen)
had the same group totals, though two individual homepage results changed.
The [current v5 profile](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json)
keeps the 50-site target and the same ordered candidate sources. It permits a
recorded ambiguous homepage result to proceed to a separately controlled
HTTP/3 test of the exact page chosen for capture. The published
[selection revision 4](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v4.json)
uses a recorded automatic public URL/domain screen; this screen makes no
claim to classify a site's content. It also records fresh unsuccessful live
operations as zero-credit screening deferrals, preserving the actual error
and available files without inferring a whole-domain problem. A
clear homepage response is therefore a useful lead, **not a requirement that
all 50 sites have clear homepages**. No selected page has yet met the complete
v5 admission checks.

The table below records the earlier v4 screen. A later screen using the clean,
repaired v5 runtime found **31 clear homepage responses, 27 inconclusive
results, six peer TLS failures, two timeouts and seven automatic skips**.
Neither screen admits a site by itself.

| Earlier outcome among 73 sites | Count | Reason for the decision |
|---|---:|---|
| Clear homepage HTTP/3 response | 30 | Keep as candidates for browser and resource checks; a successful homepage alone is insufficient. |
| Inconclusive response or connection close | 28 | The client did not obtain an accepted homepage response. V5 can still test an exact selected page; this is not a permanent site rejection. |
| Connection closed before an accepted run | 6 | A selected page or later attempt may behave differently; no site is admitted by this result. |
| Timed out after 12 seconds | 2 | The bounded homepage attempt ended; the site is not declared permanently incompatible. |
| Excluded by the automatic site-safety screen | 7 | Outside this public-page candidate screen. |

The [dated screen report](CURATED-H3-SCREEN-2026-10-02.md#exact-domains-and-observed-problem)
names **every domain** in the unsuccessful and excluded groups and records its
specific observed result. For example, `weather.com` ended with a peer `336`
close, `www.diretta.it` timed out, and `variety.com` returned a DNS answer
rejected by the public-origin policy. These are observations of this bounded
test, not general claims that the sites can never work.

The clear-response group also needs filtering. Only **14 of its 30 sites**
have at least two resource-host groups in the supplied file, and even those
groups are only hints. Technically successful sites still need the selected
page's public URL/domain screen and complete live resource checks. The initial
diagnostic browser subset used clear-response candidates such
as `poki.com`, `www.alibaba.com`, `www.bing.com`, `www.euronews.com`, and
`www.idrlabs.com`. **No site has yet been counted as an accepted class** on
the strength of this screen. The first ten fallback homepage probes were
also diagnostic only: none returned a clear result, and three local DNS
name-not-found errors prevented their v4 log from receiving verified
first-screen credit. The v5 rule classifies that exact DNS result as an
operational deferral, but it does not retroactively count the old log. A fresh
[v5 screen](CURATED-H3-SCREEN-2026-10-02.md#fresh-v5-fallback-screen-ten-verified-first-decisions)
independently verified ten first results for those fallback positions: six
timeouts, three DNS-name-not-found deferrals and one known-invalid response.
None was a clear homepage success or an accepted class.

The later browser checks show why even a promising site cannot be accepted
from the homepage test alone. An earlier `poki.com` pass produced a
268-resource browser graph with no unapproved GET requests. Preparation then
stopped at an authentication resource under the complete-resource acceptance
rule. No replayable workload or accepted class resulted. The
[dated report](CURATED-H3-SCREEN-2026-10-02.md#first-browser-follow-ups)
records that attempt and the other site-specific failures.

A fresh frozen-context attempt provides a more precise explanation of that
kind of failure. Its 260-resource input retained
`https://poki-auth.poki.com/sessions/whoami` as resource 253. Neqo completed an
HTTP/3 GET and received **HTTP 401 with a complete 157-byte body**. The saved
HEAD request also completed with status 401. The client marked those responses
failed and the overall probe partial because the legacy acceptance rule
required an acceptable application status. The observed transport exchange
itself completed; calling this result simply “HTTP/3 unavailable” would hide
the actual reason for the stop. No class is admitted by this observation.

The proposed [application response policy](APPLICATION-RESPONSE-POLICY.md)
addresses this case prospectively. It retains complete HTTP 4xx/5xx responses
only for a non-primary resource that no later request depends on. The resource,
origin, status and body remain in the graph, and `known_valid` remains false.
Primary HTML, resources needed by later requests and padding resources keep
their successful-response requirements. This policy is pending implementation
and fresh end-to-end evidence; the old failed attempts stay failed.

Fresh attempts on **3 October 2026** exposed these further concrete problems:

- **Weerplaza:** catalogue navigation attempted a WebSocket to
  `wss://onweeralarm.nl`. This traffic cannot be replayed by the current
  HTTP/3 request-graph collector, so the attempt was recorded as a screening
  deferral.
- **Albumaty:** its exact homepage passed HTTP/3, but its complete resource
  probe failed at `https://use.fontawesome.com`, covering a stylesheet and
  two font resources (IDs 5, 23 and 25). The endpoint closed during TLS with
  peer code 296. The failed probe and packet evidence were independently
  reopened; the site was not admitted on its homepage result alone.
- **Alibaba:** catalogue navigation and the exact-page HTTP/3 check passed.
  Full preparation did not reach a settled page within 30 seconds; cleanup
  also triggered the browser collector's frame-tracking check for an unknown
  frame detachment. The failed attempt remains preserved without site credit.
  The result describes this page's interaction with the collector at the time
  of testing.
- **Pinterest:** a fresh navigation attempt stopped at the browser's CAPTCHA
  detector. Its saved error did not include the page or selector matches, and
  that detector also flags ordinary CAPTCHA scripts. We therefore record an
  unresolved collection failure, not a proved visible challenge. No prepared
  workload or eligible class resulted from this attempt.

These decisions concern the observed pages and current collector. They do
not establish that every page on these domains is permanently unusable. The
[evidence index](EVIDENCE-INDEX.md#rapid-selection-revision-2-3-october-2026)
records the frozen source and receipts.

The fallback catalogue has similar operational limits. A later 40-root survey
for fallback positions 40–79 exited normally, but the frozen verifier rejected
the retained `outlook.com` peer-close code 11 because its existing error grammar
did not classify that code. The new slice therefore received no verified
first-screen credit and was not appended to the acquisition registry. The
earlier verified 0–39 prefix remains intact. Any later rule for such a bounded
operation must record an operational deferral with zero site credit, rather
than declaring that the entire domain cannot use HTTP/3 or retrospectively
promoting this log.

The final study still targets **50 eligible websites**. To reach that target,
the plan screens the usable supplied candidates first, then draws additional
candidates from the separately recorded [600-domain catalogue](../config/class-study/v1/classifier-multiorigin100-v1-candidates.json).
Every selected site, regardless of source, must pass the same prospectively
declared live browser, controlled exact-page HTTP/3, complete
cross-origin-resource, stable replay and safety checks. The proposed leaf
response rule would change the interpretation of retained application errors;
it would not remove a resource or origin. The final cohort
record will show which sites came from the supplied file and which came from
the additional catalogue. Whether these two sources can yield 50 eligible
sites is still unproven. See the [rapid study plan](RAPID-CLASS-STUDY.md) for
the 50-site capture design.
