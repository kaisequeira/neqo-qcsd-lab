# Completed HTTP error responses in the full resource graph

## Status on 3 October 2026

This document describes the **implemented, prospective rule** for
`completed-terminal-http-errors-v1`. It is not evidence that the new policy
has passed a live preparation, defense replay or capture. The frozen v5
acquisition contexts continue to use their recorded source and acceptance
rules. Their failed attempts and counters remain unchanged.

The final study target remains **50 eligible sites, five traffic conditions
and 64 repetitions per condition: 16,000 accepted traces**. A revised policy
needs explicit source/profile/runtime bindings and fresh preparation evidence
before a site can enter that cohort. The native implementation is published at
Rust commit `1cda2d2446b53d0bdee185e81755fb5115744eb1`. Its **16 focused tests
and strict library Clippy check passed** on the exact source SHA-256
`f00f7bd9ae9ade6d765ec2c6494c7e8fc44aa6329319e8613765e0f53d351d3e`.
Final Python integration passed **142 tests in 232 seconds**; all **24 new
admission cases**, five cohort/legacy checks and eight planner/adapter checks
also passed. The prospective rule is frozen in
[selection revision 5](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v5.json),
published-at timestamp `2026-10-02T21:06:26.442961Z`, raw/canonical SHA-256
`45c0e5cbdb7b5388c72d9e23de63748d085c9f027c03c06b74b2809f06a3334f`.
That revision-5 client and its installed-image checks passed. Fresh Poki replay retained
the complete 401 leaf under this rule, but 52 other requests hit a stream
limit; complete-site preparation, qualification and the new five-condition
capture checks remain outstanding. The
[evidence index](EVIDENCE-INDEX.md#application-response-policy-repair)
locates the retained commands and actual execution results.

The current prospective authority is
[selection revision 6](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v6.json),
published at `2026-10-02T22:01:23.089910Z`. It adds the primary-only body
variation rule described below. The stream-limit scheduling repair is published
at native commit `00d14c0999bf2657cacc2581e431f39bacab7281`; its **28 focused
tests and strict library Clippy passed**, and a cached native-only build
completed in **121 seconds**. A fresh native-only live replay then completed
all **260 requests in 6.617 seconds**, including 259 HTTP 200 responses and the
complete HTTP 401 leaf; the formerly blocked 52 requests completed. That
diagnostic has no matching Python-image, admission or capture claim. The
preceding 111-second build and 54-second
failed Poki attempt remain separate preserved observations. Study counters
remain **0/50 admitted sites, 0/50 shakedown traces and 0/16,000 formal traces**.

## The concrete problem: Poki replied, but the client rejected its status

In a retained frozen-context Poki preparation attempt, Neqo completed an
HTTP/3 request to `https://poki-auth.poki.com/sessions/whoami` and received an
HTTP 401 response. The GET body completed, with **157 bytes** and SHA-256
`c1ffd2a39251a8e0891f0730c8100b29b831cca065489d33159ff6868860df9a`.
The retained HEAD request also completed with status 401 and no body.

The input graph contained **260 resources**. This request was resource **253**,
an XHR, with dependencies `[0, 28, 29, 30, 246, 247]`. No other resource depended
on it, and it was not marked for padding. The legacy client still recorded
`outcome: failed`, while retaining `complete: true`, the actual status, byte
count and body hash. The GET probe stopped with `completion_status: partial`;
its retained run contains 68 complete HTTP 200 responses and this complete
HTTP 401 response. It is not a complete replay of the 260-resource input.

This distinguishes a completed application response from an incomplete
transport exchange. It does not prove that Poki meets stability, complete
graph replay or site admission requirements. The observation is the reason
to design a new rule, not permission to relabel the old run as complete.

The retained GET `run.json` SHA-256 is
`eea47f5603ae152bacebef1612806c5445e79f9b7c7cf9240c23a047ce77486a`;
HEAD `run.json` is
`4468ae7d8e9c06e430f5927ed6a6b132c453517314f6edfde4564ab096133bcb`.
These are host-local artifacts under frozen context 006, candidate
`curated-e5114f8d4f027cce4481`, attempt 000004, in its retained
`probe-output.probe-get` and `probe-output.probe-head` directories. See the
[evidence index](EVIDENCE-INDEX.md) for the surrounding source and acquisition
record. An earlier 268-resource browser pass is a separate observation.

## The proposed rule

Opt in explicitly through:

```text
preparation.application_response_policy = completed-terminal-http-errors-v1
```

Under this rule, a completed HTTP 4xx or 5xx response can satisfy execution
completion **only when all of the following hold**:

1. It belongs to an ordinary graph resource other than the primary document.
2. It is a terminal leaf: no other retained resource lists its ID in
   `depends_on`. The leaf can still depend on earlier resources itself.
3. It is not a padding resource and cannot become a response-padding candidate.
4. Its real request and response complete over the required HTTP/3 path.
5. Raw evidence retains the exact URL, resource identity, actual HTTP status,
   completed bytes and body hash. `known_valid` remains false.
6. Preparation and replay verification independently apply the same explicit
   policy to the preserved complete graph and actual response evidence.

The native scheduler can then treat this completed exchange as finished under
the declared policy and continue the remaining workload. Its recorded status
stays 401, 404, 500 or whichever status the server actually sent. The policy
does not turn an error response into an HTTP 200 response or mark it
`known_valid: true`.

| Response or resource | Proposed treatment |
| --- | --- |
| Complete 4xx/5xx response on a non-primary terminal leaf | Retain the error response; allow execution completion under the explicit policy. |
| Primary document | Require the declared successful HTML response and ordinary primary-page checks. |
| Resource used as a dependency by another request | Keep the successful-response requirement; an error cannot authorize later dependent work. |
| Padding/chaff resource | Keep normal successful-response and qualification requirements. |
| Timeout, connection close, reset or missing/incomplete body | Remain unsuccessful; there is no completed application response to retain. |
| Missing policy, malformed metadata or changed source binding | Remain a validation blocker. |

## What remains in the thesis workload

The full resource graph remains intact. No origin, URL, resource, dependency or
request header is removed to make capture succeed. Leaf error responses stay
visible in prepared manifests and raw replay evidence. All sites use the same
declared rule; it is not a Poki-only exception.

Response stability still needs fresh evidence. The implementation and verifier
must compare the retained status and body facts across the registered replay
checks instead of treating any repeated error label as proof of stability.
The selected primary page still needs controlled exact-page HTTP/3 evidence,
the complete graph must include a cross-origin resource, and ordinary safety,
source, DNS, request and capture-completeness checks still apply.

The scientific interpretation is a reproducible public-page workload including
the completed responses observed under the registered request conditions.
Authentication or other application errors are reported as observed response
facts. The resulting traffic is not a claim about every signed-in session,
browser interaction or future visit to the same domain.

## Prospective rollout and historical evidence

### Primary HTML body variation: prospective revision 6

The three preserved Poki replay attempts completed the main HTML request with
status 200, but its body varied: **58,396 / 58,281 / 58,413 bytes**, each with a
different hash. The other 207 shared complete responses kept the same status,
size and body hash. These runs still have incomplete requests and grant no
admission credit. They identify a second expected blocker after the stream
limit repair: the existing rule requires even the main HTML body to repeat
exactly.

A separate, prospective identity rule is implemented in the authoring source:

```text
preparation.primary_document_identity_policy = variable-primary-document-body-v1
```

It requires the existing `completed-terminal-http-errors-v1` application rule.
Only the unique, known-valid primary `Document` with ID 0 may vary its complete
body size and hash. The exact URL, prepared successful status, safe request
headers and complete frozen resource graph still have to match. All other
resource bodies, including HTTP error leaves, remain exact; padding response
qualification stays exact as well.

Revision-6 admission checks potential padding capacity before later
qualification: the already verified graph must contain at least one known-valid
auxiliary 2xx response on the primary origin with a stable body of **1,200
bytes or more**. Resource 0 cannot satisfy this check. The graph is preserved
when this check fails. A candidate body still needs the ordinary sustained
header and identity qualification before it can supply padding traffic; this
early check grants no chaff qualification.

The first actual native response remains recorded in `expected_responses`.
Three fresh, complete full-graph replay files retain the actual body facts for
each visit and are independently reopened, including on graphs with no error
leaf. The rule does not replace recorded body values with a wildcard or remove
requests. Its scientific scope is a fixed public-page resource graph whose
primary HTML response may vary across visits, rather than identical delivered
HTML bytes on every visit.

All **14 focused registration/admission cases**, two revision-5/6 cohort and
800-lane compatibility cases, and five targeted legacy checks passed. The raw
proof tests use controlled fixtures for native actuation, including complete
all-2xx and HTTP-error-leaf graphs; they do not establish live site eligibility.
The additional eight full-graph raw-proof/capacity/tamper cases and one legacy
graph case passed after the early capacity check was added. Revision 6 is
published create-only, with raw/canonical SHA-256
`7017fe41d41b64673abd75a7f3e0a3fc083450fff9b3264b6abd33e1ad5c7045`.
It has no live admission result yet. Revisions 1–5 keep their recorded rules,
and the old failed replay attempts gain no new credit.

The new preparation/native execution semantics must be source-bound and opted
in under newly published authority. The runtime identity must match the actual
installed client; separately frozen Python and host tooling must be recorded
as separate identities. A source change does not justify inventing a matching
old image or silently replacing a retained client binary.

Fresh bounded preparation, replay and result reopening must demonstrate the
new path before long capture uses it. A completed status-401 diagnostic alone
does not prove that all later graph requests, defenses or capture reconciliation
will pass. Changed components need the checks relevant to their new behavior;
this document imposes no repeated global build or qualification cycle.

Old contexts retain their original rules. Their partial runs, failure receipts,
raw files and counters are preserved. Old raw evidence can explain why a rule
was changed; it cannot acquire new completion or admission credit.

## Transport errors remain separate operational evidence

The fallback positions 40–79 survey illustrates a different case. Its producer
exited normally, but the frozen verifier rejected Outlook's retained
`Transport(Peer(11))` close as an unclassified operational error. No accepted
response body was available for that request. The slice was not appended to
the registry, and the earlier verified 0–39 first results remain unchanged.

That error is outside this completed-HTTP-response policy. A future bounded
root-screen deferral rule would need separate prospective authority and a
truthful retained failed-operation proof. Such a deferral receives zero site
and formal-trace credit and says nothing about permanent whole-domain HTTP/3
eligibility.
