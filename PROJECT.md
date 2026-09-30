# QCSD thesis project ledger

Checkpoint: **30 September 2026, Australia/Sydney (AEST, UTC+10)**.
This is the current research ledger. The [history](docs/PROJECT-HISTORY.md)
preserves the development record, the [class-study runbook](docs/CLASS-STUDY.md)
defines continuation, and the [capture-readiness guide](docs/CAPTURE-READINESS.md)
explains the evidence required before each capture role. The [timeline and
estimate breakdown](docs/README.md) gives the planning arithmetic. The
[operator README](README.md) covers normal Lab use.

## Goal and claim boundary

Freeze 100 public-page classes with their complete admitted multi-origin
resource graphs; fit the applicable defences on separate observations; verify
every class against all nine selectable modes; then collect the same classes
and visit counts under all eight formal conditions:

**100 classes × 20 visits × 8 conditions = 16,000 accepted formal samples.**

The formal conditions are `undefended`, `front`, `tamaraw`, `traffic-morphing`,
`wtf-pad`, `walkie-talkie`, `buflo`, and canonical CTSP `cs-buflo`. `static`
remains a compatibility control. Final certification is **100 × 9 × 1 = 900
accepted checks**. Acquisition, fitting, qualification, certification and
canaries are excluded from the formal classifier corpus.

The authorised description is **five validated defences plus two candidates /
nine selectable modes**. BuFLO and CS-BuFLO remain candidates until all final
attestation gates verify. Even after validation, describe them as validated
client-only QCSD adaptations; neither is bilateral or paper-equivalent.
Existing-defence validation does not establish compatibility on new classes.

## Current milestone

Desktop restoration and the protected historical handoff remain verified; see
the [evidence index](docs/EVIDENCE-INDEX.md) for retention boundaries. Docker
and WSL data reside on D:. The v127 browser and acquisition-only authority
passed on their historical source, but a versioned-root validator stopped
initialization. The v128 no-cache build assembled the image, then failed while
reading Buildx metadata and issued no verified build receipt. Both cohorts
remain historical evidence.

On v129, the no-cache build, pinned CDP, 110/110 browser qualification and
acquisition-only authority independently verified on the clean source below.
`acquisition-init` created the versioned checkpoint. The watcher then stopped:
`tranco-0000697` has a `probe-window-missed` terminal after recoverable probe
retries exceeded the admissible window; `tranco-0000984` has a durable internal
acquisition error when redirect dependency evidence did not match the redirect.
The checkpoint contains **zero accepted pilot classes**. Preserve its failed
attempts and receipts. A standalone, non-evidentiary diagnostic using the v129
image found a successful `cloudflare-quic.com` Neqo control probe
(`known_valid=true`), while `consultant.ru` and `www.consultant.ru` each
returned `Error: Timeout(12)` on the default Docker bridge. That diagnostic
has no formal receipt and cannot reclassify v129. The redirect evidence producer
has been corrected, and a prospective pre-baseline HTTP/3 reachability screen
has been implemented for the next cohort. Both require a fresh cohort with
complete downstream reproof; v129 cannot be resumed under changed source or
promoted into an accepted pilot.

On v130, the corrected source passed the no-cache build, pinned CDP and the
independently verified 110/110 browser qualification. Acquisition authority
then failed its creation-time correctness suite before publishing a receipt:
the watcher and authority declared different test lists, and watcher tests
assumed a user-systemd socket that is absent in the qualification container.
The host watcher suite passed 379 tests with only the list mismatch failing.
The v130 browser receipt remains valid for its source, but it cannot authorize
acquisition under corrected source. No new acquisition checkpoint was created.
A bounded v130-image diagnostic subsequently hit a root CDP
`InvalidInterceptionId` while navigating `consultant.ru`. `elmundo.es`
navigation completed, then its selected page origins each timed out twice in
the prospective HTTP/3 screen while both control probes passed. These are
engineering observations outside any acquisition checkpoint and add no
scientific numerator.

| Checkpoint identity | v130 desktop qualification and current state |
|---|---|
| Lab branch and v130 source commit | `desktop-portability-2026-09-26`; `5fe0da7a8a8dc92713d91fb67b65f265325e4d51` |
| Rust commit and Lab Gitlink | `e8575fd8e54921ed6ff867de475b4a734064866e` |
| Build and pinned CDP | `artifacts/buflo-study/build-execution-v130.json` and `artifacts/buflo-study/pinned-cdp-execution-v130.json`: independently verified on their bound source |
| Browser execution | `artifacts/buflo-study/browser-egress-qualification-v130/final.json`: independently verified 110/110 |
| Desktop authority | v130 creation failed its correctness suite; no authority receipt issued |
| Acquisition checkpoint | v129 remains the latest initialized checkpoint, with 0/120 accepted |
| Next execution | Finish and preflight prospective schema-2 acquisition authority; allocate a fresh cohort, reprove build and pinned CDP, create authority, then start bounded acquisition. Defer the full 110-vector browser gate to the same-source full foundation before fitting or defence capture |

Preserve the v130 qualification evidence and failed authority attempt, the v129
checkpoint and failed attempts, v128 failed build, v127
receipts and failed initialization, v126 checkpoint and failed watcher journal,
and the earlier v124 failure and v116 incomplete laptop execution. Historical
evidence cannot authorise changed source or supply a scientific numerator.

| Extended study scientific milestone | Accepted at this checkpoint |
|---|---:|
| Eligible pilot classes | 0/120 |
| Frozen final classes | 0/100 |
| Pilot fitting / qualification / compatibility | 0/480; 0/720; 0/1,080 |
| Authoritative fitting / final qualification | 0/2,000; 0/600 |
| Final nine-mode certification | 0/900 |
| Pre-block canaries | 0/1,000 |
| Formal matched capture | 0/16,000 |
| Final handoff, evaluation, comparison and attestation | Not produced |

Attempted acquisitions, local test passes and historical browser gates are
engineering progress. None supplies an accepted numerator for this table.

## Outputs already established

| Output | What it establishes |
|---|---|
| 120-sample historical fitting campaign | Six workloads × two policies × ten visits; produced Traffic Morphing, WTF-PAD and Walkie-Talkie inputs |
| 14-sample seven-mode smoke | Two workloads accepted across the established seven modes on their recorded source |
| Sealed `classifier-multiorigin5-v2` | 2,500 samples: five classes, 1,500 undefended, 500 FRONT, 500 Tamaraw; 12,503 checksum entries |
| Candidate implementations and reference pipeline | BuFLO/CS-BuFLO interfaces, client/transport evidence, independent oracle and source comparison mechanisms implemented; final live validation pending |
| Extended-class pipeline | Frozen 600-candidate sampling frame, acquisition/stability, fitting, selection, nine-mode certification and formal/evaluation contracts implemented |
| Historical completed browser gates | Demonstrate their specific source versions; subsequent acquisition/runtime fixes require new authority |

The five-class handoff is a classifier-pipeline pilot. Its protocol uses
undefended blocks 1–8 for training, block 9 for validation and block 10 for
testing; FRONT and Tamaraw are inference-only. It does not establish efficacy
for the new 100-class study. Its bytes and checksums are protected before and
after formal capture.

The detailed chronology—including failed cohorts, timing/credit fixes,
browser lifecycle corrections and infrastructure interruptions—is retained in
[PROJECT-HISTORY.md](docs/PROJECT-HISTORY.md). The
[source map](docs/HISTORY-SOURCE-MAP.md) accounts for the consolidated ledgers.

## Architecture and implemented boundaries

```text
papers + pinned author sources -> isolated reference/oracle receipts
prepared multi-origin workload -> Rust client -> ordinary HTTP/3 servers
                                      |
                              packet + runtime evidence
                                      |
Lab admission + verification -> sealed results -> handoff -> evaluation
                                                      -> final attestation
```

The Lab and nested Rust repositories have independent Git histories. Docker
binds execution to clean source, image, parameter, workload and qualification
identities. Production defence code is clean-room; pinned author code runs
only in the isolated reference environment.

| Stable identity | Runtime participation | Inputs and status |
|---|---|---|
| `undefended` / `none` | No defence shaping | Baseline |
| `static` | Configurable `ChaffOnly` / `ChaffAndShape` | Explicit schedule; control |
| `front` | `ChaffOnly` | Fixed selected profile; validated defence |
| `tamaraw` | `ChaffAndShape` | Fixed selected profile; validated defence |
| `traffic-morphing` | `ChaffOnly`, reactive size shaping | Workload-bound fitted matrix; validated defence |
| `wtf-pad` | `ChaffOnly` | Fitted histograms; validated defence |
| `walkie-talkie` | `ChaffAndShape` | Fitted pairing/mould and qualified prefixes; validated defence |
| `buflo` | `ChaffAndShape` | Versioned `--buflo-parameters`; candidate |
| `cs-buflo` | `ChaffAndShape` | Versioned `--cs-buflo-parameters`; candidate |

BuFLO uses exact 1,200-byte outgoing UDP cells, a 20 ms cadence, tick zero and
an inclusive minimum duration, with strict half-open 5 ms realisation windows
and no catch-up. Current evidence includes kernel transmission and independent
post-veth observation. Incoming opportunities are client receiver-credit/chaff
actions; actual server cell sizes and timing are not reproduced properties.

CS-BuFLO uses a 600-byte UDP-payload adaptation, real-bearing byte/timing
observations, bounded power-of-two rate adaptation and discrete jitter.
Canonical CTSP and controlled CPSP variants differ in padding accounting.
Congestion-sensitive full, partial or suppressed opportunities need matching
transport evidence. Local completion/quiet/termination semantics are distinct
from bilateral server padding-complete signalling. Detailed algorithm and
historical schema descriptions remain in the history and methodology.

## Next actions and cheapest-first execution

The v129 acquisition-only gates passed and its versioned checkpoint initialized,
but the watcher stopped before accepting a pilot class. The redirect dependency
producer is corrected and the prospective schema-11 pre-baseline HTTP/3 screen
is implemented in source. If the first known-good Neqo control fails, the screen blocks without
running candidate or second-control probes. Otherwise it runs two attempts per
distinct selected-page URL request origin, then the second control. An origin
passes only with two `known_valid=true` results and fails only with two
classified connectivity timeouts. With both controls passing, a candidate is
technically rejected if at least one origin fails and every other origin has
a definite pass or fail. Any mixed or ambiguous origin blocks, even when
another origin fails. The screen covers
selected-page request origins only; third-party resource origins discovered
during timed preparation can still cause a missed-window blocker. It does not
prove that a complete page graph can be prepared. Preserve v129 as failed
evidence. After source freeze, allocate a fresh source-bound
cohort and repeat every downstream gate before initializing a new acquisition
root. The v129 missed window remains an unresolved historical blocker, not a
selective site rejection.
The supplied curated domain list has been imported as a portable, hash-bound
source receipt at
[`config/curated-sources/crux-73-v1.source.json`](config/curated-sources/crux-73-v1.source.json).
It contains 73 domains and 5,507 historical resource-URL observations; seven
domains match the existing pre-browser safety policy. This source receipt
assigns no eligibility and supplies no live workload. On 28 September the
user chose to retain the existing frozen catalogue for formal acquisition;
the curated receipt is excluded from that run. The registered 600-candidate,
120-pilot, 100-final-class contract remains in force.

1. Preserve the verified migration manifests, historical handoff, v126 through
   v129 receipts and checkpoints, and the failed watcher evidence.
2. Retain the registered Tranco candidate catalogue for this formal run.
3. Freeze the corrected schema-11 source; obtain the next unused cohort,
   fresh no-cache images, pinned-CDP and
   110/110 browser qualification. Publish new acquisition authority.
4. Initialize a new versioned acquisition root and acquire the 120-class pilot
   with two genuine short-horizon prepared observations per admitted page.
   The prospective watcher can admit a later batch 60 seconds after all
   members of the prior batch are scientifically terminal and its Docker scope
   is empty; unresolved batches retain the 40-minute collision envelope.
   Complete the full defence foundation
   before any class-study fitting or capture.
5. Follow pilot fit/qualification/compatibility, final selection, authoritative
   fitting, final qualification and 900-cell certification.
6. Freeze readiness and historical pre-snapshot; interleave ten canary blocks
   with ten formal blocks; seal, export, evaluate, compare and attest.

The [runbook](docs/CLASS-STUDY.md) gives stage purposes, exact matrices,
prerequisites, retry rules and commands. Diagnostic passes cannot replace
mandatory evidence. New host/source identities require fresh authority; an
ordinary unchanged-source interruption may resume under the existing contract.

## Interpretation and maintenance

This is a closed-world HTTP/3 prepared-resource replay study. The browser
discovers the admitted graph; Neqo's replay is not unrestricted interactive
browsing. Preserve and report naturally multi-origin classes without selecting
for an origin count. Classifiers see only relative packet time, direction and
observer-frame length, with no identity or payload metadata. Compare papers
using their actual transport, dataset and metric definitions; numerical
proximity alone is not validation. See [METHODOLOGY.md](METHODOLOGY.md).

Use source and pinned Gitlink, checked-in specifications, immutable executed
receipts, then explanatory prose to resolve implementation questions. Receipts
establish what ran on their bound source; current source never retroactively
upgrades an older execution.

After each terminal milestone, update accepted counts and the next action,
append the evidence-backed outcome to history, and index new evidence.
Include operational failures and supersession reasons without counting them
as scientific failures. Keep machine paths and transfer credentials outside
Git. Update documentation in an authoring clone between live operations and
leave execution checkouts pinned. Never call the final campaign ready until
acquisition, fitting, qualification and all 900 certification cells verify.
