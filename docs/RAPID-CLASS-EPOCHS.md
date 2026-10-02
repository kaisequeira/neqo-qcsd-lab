# Recovering when a website changes

This is a **prospective change to the rapid study protocol**. It must be
declared before its first affected capture. Historical v4/v5 plans, failures
and receipts retain their original rules. The implementation is in
[rapid_class_epochs.py](../src/qcsd_lab/rapid_class_epochs.py); local fixture
tests are engineering checks and do not prove that a public website has
passed, or that any formal traces have been collected.

## The problem

A live website can change while we collect data. A resource's new body may
fail the identity recorded during preparation. Retrying the same frozen
workload cannot repair that mismatch. Replacing the entire study would
unnecessarily discard the usable work from other sites and time periods.

The original recovery generation, such as `g02`, still means a fresh physical
attempt using the **same** workload, client, image and traffic settings. It
cannot silently refresh a website or change its scientific class label.

## What stays fixed

The original, independently verified final-50 cohort fixes:

- All 50 class identities and their order.
- The exact selected page URL for each class.
- The ten groups of five sites.
- Undefended, FRONT, Tamaraw, BuFLO and CS-BuFLO conditions.
- Sixteen time blocks and four visits per site per condition in each block.
- The registered traffic settings, runtime image, client and source bindings.

The total remains **50 × 5 × 16 × 4 = 16,000 accepted formal traces**.
Diagnostics and failed or retired block attempts are additional.

## A class epoch is a dated version of one site's workload

An epoch keeps the same class ID and selected URL. It binds one immutable
prepared workload and its complete graph, including every discovered resource
and origin. The initial epoch reopens the original admitted bytes. A refresh
needs fresh preparation and its original raw JSON evidence, including three
complete HTTP/3 replays, under the original cohort's response policy.

Response comparisons are delegated to that registered policy. The epoch
mechanism does not itself waive body matching or authorize primary-document
content variation. Any such rule needs its own prospective admission and
capture policy. Refreshes cannot repair a page that fails that policy on every
request.

The changed workload receives a new filename. The old manifest, response
ledgers, body hashes and source records remain intact. A fresh graph may
reflect genuine changes observed by the browser; it cannot be edited to
remove troublesome resources or origins.

Only the changed class needs new response-only chaff qualification. Its new
sidecar can join four unchanged, independently reopened sidecars in a new
immutable five-site named set. The set is bound to the actual collection
image, client and implementation. Existing named-set publication validates
and copies those files; it does not repeat network qualification for the
unchanged four sites.

## All five conditions form one comparable block

Before capturing a five-site group, publish one block declaration containing
its exact five-class epoch vector and qualifier. All five conditions use that
same vector. Each condition contributes 20 accepted traces:

**5 sites × 4 visits = 20; five conditions = 100 traces per matched block.**

A condition's completion is conditional evidence. The block obtains formal
credit only through an explicit commit after all five conditions independently
deep-verify. The commit selects their exact receipts; the verifier never
chooses whichever files happen to be newest.

If a later condition finds response drift:

1. Preserve the actual failed capture and all earlier conditions in that block.
2. Reopen the sealed failure and original `run.json`; confirm complete
   application responses actually differ from the frozen identity. Transport
   loss, a timeout or an arbitrary error message cannot authorize a refresh.
3. Confirm all attempted host/supervisor processes have ended. Retain actual
   lifecycle and Docker observations while both ownership locks are held.
4. Publish the zero-credit block retirement.
5. Prepare the drifting class again, at its original selected URL, and verify
   its complete fresh graph and raw replay evidence. Register its new epoch.
6. Assemble a fresh five-site qualifier, declare a replacement block and
   capture all five conditions against that newly declared vector.

An earlier completed condition in the retired block stays valid evidence of
what was captured, but is not mixed with newer website bytes for formal
comparison. Other committed blocks keep their evidence and credit unchanged.
At most the affected **100-slot block** needs replacement. A committed block
cannot later be replaced to improve results.

The replacement must use the drifting class's newly registered epoch bound to
that retirement. Unaffected members retain their previous exact epoch vector.
It cannot merely recapture the same vector under another name or replace an
unrelated class. Ordinary retries independently confirm that the predecessor
was actually incomplete; a missing receipt for a complete capture never makes
it eligible for recapture. Failed predecessors and their raw capture files are
hash-bound by successors and disclosed again by the block commit.

The block namespace, for example `e0002`, is separate from transient lane
retries such as `g02`. A new block starts each condition at its own first
generation, even if the old block never reached that condition.

## Operator entry point

Use the frozen study overlay and the unchanged portable final-50 capture spec:

```bash
PYTHONPATH="$rapid_source/src" python3 -m qcsd_lab.rapid_class_epochs --help
PYTHONPATH="$rapid_source/src" python3 -m qcsd_lab.rapid_class_epochs initialize \
  --spec "$capture_spec" --evidence-root "$epoch_evidence"
```

The epoch evidence directory must be new and empty, beneath the spec's mounted
data root. Initialization actually executes the bound collection-image plan
check before publishing the policy and 50 initial class receipts. It grants
zero capture credit.

`declare-block --block N --shard N --qualification-manifest PATH` declares its
five conditions. Use repeatable `--class-epoch CANDIDATE=PATH` arguments for
explicit refreshed class receipts; unspecified members retain their original
epoch. Replacement declarations also require `--predecessor-retirement PATH`.

`launch-lane --declaration PATH --mode MODE` uses the existing locked host
actuator, actual installed-image check, immutable client/source bridge and
full-graph DNS pins. Its `--generation 2 --predecessor-intent PATH` form only
retries an actual incomplete immediate predecessor in the same block epoch.
Generic resume is not used.

The host launcher rejects an epoch name without explicit launch authority
before Docker preflight. Before public DNS or capture topology, a separate
read-only execution inside the bound image reopens the actual intent hash,
campaign, class vector, source bridge and current qualifiers. A filename or
environment value alone cannot authorize an epoch, and a completed or retired
intent cannot be used again.

`retire-lane`, `retire-block`, `register-class`, `verify-lane`, `complete-lane`
and `commit-block` have explicit required inputs shown by their `--help`.
`register-class` consumes the actual fresh prepared workload, its complete
graph and observed block retirement; it is not a substitute for running
preparation or qualification.

`publish-manifest` and `verify-manifest` execute final closure inside the bound
collection image. Closure reopens **160 explicit matched commits**, their
800 selected lanes, every attempted predecessor block, and each class's
64 traces per condition. Missing conditions, mixed vectors, hidden unfinished
attempts, repeated commits or silently skipped epochs fail closure.

## Limits

This implementation serializes capture through the existing guardian. It
does not establish parallel-container fidelity or throughput. A source,
client, image or traffic-setting repair still needs a separately declared
targeted proof protocol; `g02` and website epochs cannot authorize it.

Fixture tests replace Docker, admission and packet-seal verification at their
external boundaries. Before relying on this path for a long study, run a
bounded real matched-block capture and recovery trial. A local passing test
cannot supply the requested 16,000-trace corpus or a live website's admission.
