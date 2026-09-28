# QCSD thesis project ledger

Checkpoint: **28 September 2026, Australia/Sydney (AEST, UTC+10)**.
This is the current research ledger. The [history](docs/PROJECT-HISTORY.md)
preserves the development record and the [class-study runbook](docs/CLASS-STUDY.md)
defines continuation. The [operator README](README.md) covers normal Lab use.

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
and WSL data reside on D:. Source-bound v124 produced a verified native
three-image build, ETF capability probe and pinned-CDP result. The 110-vector
browser-egress gate stopped after 28 passing vectors: vector 29 has a sealed
operational-failure receipt for a Docker API inspect timeout. Its open evidence
inventory validates, but there is no final browser receipt or acquisition
authority. The 28-vector prefix advances no scientific count. Three separate
2,048-sample ETF/veth diagnostics remain incomplete and non-evidentiary.

| Checkpoint identity | v124 desktop execution and current state |
|---|---|
| Lab branch and v124 source commit | `desktop-portability-2026-09-26`; `23cee75f3f7dec784776f5e128636317e63f2861` |
| Rust commit and Lab Gitlink | `e8575fd8e54921ed6ff867de475b4a734064866e` |
| Build and pinned CDP | `artifacts/buflo-study/build-execution-v124.json` and `artifacts/buflo-study/pinned-cdp-execution-v124.json` verified on their bound source |
| Latest browser execution | `artifacts/buflo-study/browser-egress-qualification-v124/`: 28/110 passed, vector 29 operational failure, no `final.json` |
| Desktop authority | No acquisition authority; pilot and formal collection remain at zero |
| Next execution source | Docker inspect retry and curated-source importer validated locally; no source-bound gate has run on this later source |

Preserve the v124 failure and the earlier v116 incomplete laptop execution.
Neither can authorise changed source or substitute for a complete browser gate.

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

The v124 browser failure is an operational Docker API observation fault, not a
semantic vector rejection. The browser container later inspected as exited
with code zero. The bounded retry passes local tests but needs a fresh
source-bound cohort for qualification.
The supplied curated domain list has been imported as a portable, hash-bound
source receipt at
[`config/curated-sources/crux-73-v1.source.json`](config/curated-sources/crux-73-v1.source.json).
It contains 73 domains and 5,507 historical resource-URL observations; seven
domains match the existing pre-browser safety policy. This source receipt
assigns no eligibility and supplies no live workload. On 28 September the
user chose to retain the existing frozen catalogue for formal acquisition;
the curated receipt is excluded from that run. The registered 600-candidate,
120-pilot, 100-final-class contract remains in force.

1. Preserve the verified migration manifests, historical handoff, v124 build,
   pinned-CDP receipt and incomplete browser checkpoint.
2. Retain the registered Tranco candidate catalogue for this formal run.
3. Freeze clean source; obtain the next unused cohort, fresh no-cache images,
   pinned-CDP and 110/110 browser qualification. Publish acquisition authority.
4. Acquire the 120-class pilot with genuine longitudinal observations. Complete
   the full defence foundation before any class-study fitting or capture.
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
