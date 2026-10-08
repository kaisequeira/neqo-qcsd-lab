# Prospective FRONT incoming timing adaptation

## Why the rule is changing

The first FRONT V5 practice completed the full resource graph and every
scheduled padding slot. Two incoming credit advertisement intervals exceeded
the Lab's 10 ms acceptance window; the largest conservative bound was
25.51 ms. That practice remains failed. The new prospective rule permits up
to 50 ms for this incoming timing measurement so the study can use a declared
local scheduling allowance while retaining the actual Native timing results.

This is a client-only QUIC/Lab adaptation. It does not establish equivalence
to paper FRONT or to server-controlled packet release.

## Exact declaration

Select the additional Lab field explicitly:

```yaml
front_incoming_credit_acceptance_policy: rapid-front-v5-local-credit-jitter50000us-acceptance-v1
```

It requires the existing explicit Native FRONT V5 configuration selection,
whose frozen configuration SHA-256 is
`910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996`.
An absent field keeps the earlier acceptance rule. Null, unknown strings,
another traffic mode or a different Native configuration are rejected.

## What the measurements mean

The new helper uses the conservative process `CLOCK_MONOTONIC` interval for
credit advertisement. Incoming acceptance requires that complete interval to
fit the declared half-open 50,000 µs window. Metrics include the selected
policy, its window and independently recomputed violation count.

Native still uses its 10,000 µs control interval and release window. Its
10 ms violations, the historical 5 ms diagnostic and the maximum observed
lateness remain recorded separately. The Lab field is not a Native marker,
and changing stored counters cannot substitute for recomputing raw evidence.

The outgoing release window remains 10 ms, with its original 9 ms
construction interval, 1 ms reserve and 10% omission cap. Full resource and
origin graphs, complete application delivery and source/runtime checks
remain required. The separate ordinary packet/client clock-alignment limit
remains 10 ms.

## How fresh capture becomes eligible

1. Prepare matching installed Lab images using the unchanged verified Native
   client where the cached-runtime contract permits it.
2. Declare a fresh empty FRONT condition with the new field and exact source,
   client, configuration and image identities before capturing.
3. Run the affected FRONT qualification and a fresh complete-graph canary.
4. Independently deep-verify that canary and close its readiness receipt.
5. Publish bounded formal lanes under that condition; deep-verify their traces
   before adding accepted visits to the ledger.

Existing ordinary rows keep their original measurement identities and proofs.
Earlier FRONT failures cannot be promoted under this new rule. A later bug
fix must preserve unaffected lanes and prospectively repair the affected
condition where required by its actual runtime or acceptance change.

## Review and software checks

The new helper is [front_incoming_acceptance.py](../src/qcsd_lab/front_incoming_acceptance.py).
[Focused controls](../tests/test_front_v5_incoming_acceptance.py) cover explicit
selection, boundary cases, separate counters, tamper refusal, Native/config
joins, complete capture/deep validation, plan propagation and preservation of
old scientific readers. See [the evidence index](EVIDENCE-INDEX.md#source71-front-incoming-timing-adaptation)
for the actual checkpoint and remaining physical proof.
