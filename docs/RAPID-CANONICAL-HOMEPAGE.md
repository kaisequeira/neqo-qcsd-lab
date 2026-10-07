# Prospective homepage selection for rapid capture

The study still needs **50 eligible multi-origin sites, five traffic settings
and 64 accepted visits per site and setting: 16,000 recordings**. This change
helps choose the starting page for future site discovery. It does not grant
site or recording credit.

## Why the starting URL matters

Some catalogue homepages redirect from `https://example.com/` to
`https://www.example.com/`. Starting browser discovery at the first address
records that redirect as part of the resource graph. The Native GET check
requires a successful 2xx response for every recorded resource, so that graph
can fail immediately even though its destination page is available.

For new V13 attempts, a bounded check resolves the homepage **before the
browser starts**. The original catalogue candidate stays unchanged. The
chosen destination is recorded separately, and discovery starts there.
Previously collected graphs keep every original request and their original
outcome. This policy does not repair an old graph by removing its redirects.

## What the early check records

The [resolver](../tools/whole_graph_discovery_v13/canonical_homepage.py) records
the original URL, DNS answers, selected public peer, verified TLS hostname,
response status, redirect headers and final starting URL. It allows at most
eight redirects, seven seconds per hop and 45 seconds overall.

The destination must remain HTTPS and within the original candidate's
registrable domain, under the existing query-free HTML URL policy. Private
network addresses, credentials, unsupported ports, queries and fragments are
refused. A successful final response must identify HTML. The check reads
headers only; it proves neither complete body delivery nor HTTP/3 support.

## What still has to pass

1. Browser discovery must retain the complete graph from the declared starting
   page, including repeated requests, dependency edges and every resource
   origin. Existing convergence and discovery guards remain in force.
2. The independent Native GET preparation must successfully fetch that entire
   graph under the registered protocol, response and size rules.
3. The prepared graph must have the required multiple origins before the site
   is admitted. A redirect observed only during homepage resolution does not
   supply an extra graph origin.
4. Each traffic setting needs its own matching preparation and readiness
   evidence. Formal traces count only after deep verification and ledger
   admission.

These checks distinguish an available homepage from an eligible replayable
site. A failed attempt remains a recorded operational failure.

## Reusing the producer across batches

The tracked [operator](../tools/whole_graph_discovery_v13/operator.py) declares
the next candidates from a genuine predecessor plan and closed batch. For an
existing study continuation, its command shape is:

```sh
python3 -I -B tools/whole_graph_discovery_v13/operator.py declare \
  --previous-plan PREVIOUS_PLAN.json \
  --previous-batch PREVIOUS_BATCH.json \
  --count 5 --output NEW_PLAN.json
```

Use `operator.py run --help` for the recorded Docker discovery arguments.
Its recorder must be the authenticated recorder declared by the study. The
source checkout, plan, source hashes, image and output roots are bound to the
attempt; every new output namespace is create-only.

The run performs the full historical HOST check once, records its actual
completion and complete dependency fence, and reopens that closure before
physical discovery and later input verification. Missing or changed evidence
is refused. The next batch can use the same frozen producer without another
source commit or image build just because candidate positions changed.

The external producer and reader identities remain separate from the
installed browser and Native client identities. Reuse does not claim that
new external code was installed in an older image.

## Portable source bindings and capture recovery

Portable V2 source bindings retain both the measured Git checkout permissions
and the installed image permissions, plus exact file bytes and Git identities.
The [local source cache](../src/qcsd_lab/rapid_action_local_source_facts.py)
preserves both roles and rechecks their complete binding before registration.
It also fences installed files, import membership, Git metadata and raw
operation evidence. Historical V1 bindings retain their strict permission
rule.

A reader correction can therefore reopen saved recordings under a separately
verified consumer. It does not change their source labels or traffic settings,
and it does not itself require recapture or Native compilation. A change to
traffic, workloads or acceptance rules needs a prospectively declared lane
with the affected checks.

See [the rapid capture path](RAPID-CAPTURE-PATH.md) and
[the rapid study specification](RAPID-CLASS-STUDY.md) for the capture workflow.
