# Proposed 20-site class study

**Status: implementation in progress; no capture authority.** The
[profile](../config/class-study/v2/study.json) is a prospective proposal for
`classifier-multiorigin20-v1`. It does not change or approve any result from
the [registered 100-site study](../config/class-study/v1/study.json). The
[project ledger](../PROJECT.md) and [evidence index](EVIDENCE-INDEX.md) remain
the authority for completed gates and accepted counters.

## Why change the site count?

The registered study needs 24 eligible pilot sites in each of five Tranco rank
groups, then 100 final sites. A zero-credit check of the 600 frozen candidate
homepages found only 63 with confirmed HTTP/3, distributed 2, 6, 17, 14 and
24 across those groups. Browser-selected inner pages may still qualify, so
the survey does not prove that the original target is impossible. It does make
a fast 120-site pilot unlikely enough that a smaller protocol should be tested
before another long source-bound build.

The proposed study retains the same 600-candidate catalogue and its frozen
within-group ordering. It would search across the groups in a declared
round-robin order and seek **30 fully evidenced pilot sites**. It would select
**20 final sites** and **10 reserves**, with no fixed minimum from any one
rank group and no more than 10 final sites from a group. The observed rank
mix and every site that cannot be measured would be reported. A site with a
browser or collector fault cannot be called a scientific rejection or an
eligible site merely to advance the list.

The profile explicitly inherits the base study's schema-4 Walkie-Talkie
prefix qualification with scope `primary-origin-capacity-v1`. The full
prepared multi-origin graph remains bound to the prefix specification, while
the capacity proof covers staged bytes on one primary-origin QUIC connection.
Secondary-origin and later-component resources receive no prefix capacity
credit; full-page replay and certification must establish their behaviour.
Historical schema-2 and schema-3 prefix evidence receives no new-study credit.

## What must pass before final collection?

1. Freeze clean Lab and pinned Rust source, build fresh images, pass the early
   browser connection and acquisition-authority checks, and register a new
   acquisition run for this exact profile. Old builds and receipts remain
   verifiable only for their original source and study contract.
2. Acquire 30 eligible pilot sites with deep-verified site, page, resource,
   HTTP/3 and prepared-workload evidence. Record every earlier candidate in
   the declared order, including scientific rejections and any separately
   authorized operational censors. A missed window or general infrastructure
   failure still blocks admission.
3. Pass the complete browser, reference, code and traffic-defence foundation
   on the same source. Early acquisition permission alone does not authorize
   fitting or defended traffic capture.
4. Make **120 pilot fitting visits** and **up to 180 pilot defence checks**
   (120–180 for the 20–30 sites with feasible pair prefixes).
   Plan 15 non-overlapping Walkie-Talkie pilot pairs. Pair screening has its
   own deep-verified receipt with an outcome for every planned pair; it is
   not a 30-site nine-mode compatibility campaign. A deterministic prefix
   capacity failure can mark a pair unqualified without live sidecars for its
   endpoints; a missing sidecar or live error for a pair needing qualification
   blocks screening instead of counting as a failure. A failed pair stays in
   the receipt and cannot enter the final set. Choose the first 10 qualified
   pairs in the registered pilot order that satisfy the rank cap. Stop if no
   valid 10-pair choice
   exists. Classifier accuracy and final traffic results cannot influence
   site or pair selection.
5. Freeze the 20 final sites and 10 reserves, then make **400 final fitting
   visits**, **120 final defence checks**, and **180 nine-mode certification
   visits**. Final fitting uses the ten Walkie-Talkie pairs selected from the
   pilot evidence and fits their traffic moulds from the final traces; it does
   not reselect pairs using those later traces. The final pairing remains the
   pilot-qualified choice, and its recorded cost describes those fixed pairs
   on the final traces. A different pairing fails verification. Verify all
   receipt, source, workload and
   historical-archive bindings before authorizing the long run. The five
   preparation stages total **940–1,000 visits and checks**: 120 + (120–180) +
   400 + 120 + 180.
   The profile registers 1,000 as the planning maximum; none counts toward
   the 16,000 final samples.
6. Complete ten temporal blocks. Each block has **20 ordinary site health
   checks** and **1,600 final traffic recordings**: 20 sites × 8 formal
   conditions × 10 visits. Ten verified blocks give **200 health checks plus
   16,000 accepted samples**. Failed attempts remain recorded and count only
   after the prescribed verified replacement succeeds.

At the older measured 63–131 seconds per visit, the 940–1,000 preparation
visits and checks would take roughly **16–36 hours** if checks take as long as
those visits, and the 16,200 final visits would take
about **12–25 days**. These are arithmetic planning ranges, not completion
forecasts. Screening, code work, review, repairs, retries and public-site
changes are additional unknowns. The [acquisition rehearsal guide](ACQUISITION-REHEARSAL.md)
explains which early live checks carry no scientific credit.

## Claim and analysis boundary

The final matrix remains **20 sites × 8 conditions × 100 visits = 16,000
samples**, with 80 training, 10 validation and 10 held-out visits per site
and condition across the ten blocks. Random guessing among 20 sites has a
5% accuracy baseline. Repeated visits to one site are correlated; uncertainty
must be calculated at the site or workload level, and rank distribution must
be reported. This supports a closed-world, longitudinal comparison of the
defences on 20 measurable sites. It does not support a 100-site result or a
claim that the sites represent all Tranco ranks.

The new profile can become authoritative only after its selection, pairing,
fitting, campaign, receipt, readiness, handoff and evaluation code and tests
pass as one source-bound chain. Until then, its counts are planned targets and
the accepted final-sample counter remains zero.

## First official acquisition run

These commands are for **this 20-site profile**. The existing
[100-site runbook](CLASS-STUDY.md) uses different authority and acquisition
paths; do not copy those paths into this run. Finish the cheap tests and live
diagnostics in the [acquisition rehearsal](ACQUISITION-REHEARSAL.md), freeze a
clean Lab commit with a clean pinned Rust Gitlink, and use the cohort allocator
and retained claim ledger to choose an unused version. An attempted version is
not reusable just because its final receipt is absent.

Set the paths once in a shell in the Lab directory. The value of
`COHORT_VERSION` below must come from the allocator check, not from a previous
chat or an example number:

```shell
: "${COHORT_VERSION:?set the allocator-authorised unused cohort}"
BUILD="artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json"
PINNED_CDP="artifacts/buflo-study/pinned-cdp-execution-v${COHORT_VERSION}.json"
AUTHORITY="artifacts/classifier-multiorigin20-v1-acquisition-authority-v${COHORT_VERSION}.json"
ACQUISITION_ROOT="artifacts/classifier-multiorigin20-v1-acquisition-v${COHORT_VERSION}"
```

Run each command below **one at a time**. Check its exit status and final
receipt before running the next command. Stop and diagnose a failed gate;
preserve its files and claim.

```shell
./qcsd-lab build --cohort-version "$COHORT_VERSION"
./qcsd-lab test pinned-cdp --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --destination "$PINNED_CDP"
./qcsd-lab class-study acquisition-authority \
  --study-id classifier-multiorigin20-v1 --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --pinned-cdp-receipt "$PINNED_CDP" \
  --destination "$AUTHORITY"
./qcsd-lab class-study verify --study-id classifier-multiorigin20-v1 \
  --target "$AUTHORITY"
./qcsd-lab class-study acquisition-init \
  --study-id classifier-multiorigin20-v1 \
  --candidate-catalogue config/class-study/v1/classifier-multiorigin100-v1-candidates.json \
  --acquisition-root "$ACQUISITION_ROOT" \
  --acquisition-authority "$AUTHORITY" \
  --acquisition-started-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
./qcsd-lab class-study acquisition-watch \
  --study-id classifier-multiorigin20-v1 \
  --acquisition-root "$ACQUISITION_ROOT" --max-actions 1
```

The first watcher call is deliberately bounded to one action. Inspect the
checkpoint, its pending and terminal candidates, and the saved action result
before allowing more actions. The initializer creates separate versioned
stability and workload roots alongside `ACQUISITION_ROOT`. The 600-candidate
file is the same frozen catalogue used by the older study; this profile sets
its own round-robin order and 30-site completion rule. The later 110 browser
checks and full defence foundation must pass on this same source and build
before fitting or defended capture can count.
