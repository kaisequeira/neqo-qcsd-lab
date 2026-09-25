# History migration validation receipt

Validation date: **25 September 2026, Australia/Sydney (AEST, UTC+10)**.

This receipt validates the portable documentation migration. It is not a Lab
runtime, browser, defence or scientific-capture receipt. The current
[project ledger](../../PROJECT.md), [runbook](../CLASS-STUDY.md) and
[evidence index](../EVIDENCE-INDEX.md) remain the operational entry points.

## Original source identities

The byte-exact originals are private migration-bundle members. The five
workspace-root files that still existed during validation compared byte for
byte with their bundle copies. The pre-rewrite 251-line Lab README had already
been replaced in the working tree, so its bundle hash is its retained identity.

| Source member | Bytes | Lines | Headings outside fences | SHA-256 |
|---|---:|---:|---:|---|
| `PROJECT.md` | 470,494 | 4,917 | 47 | `36a9a72c40d01fb4453dd8479906dc010e2a0dd6c0e974984d776dd88531c150` |
| `PROJECT-HISTORY.md` | 66,625 | 1,029 | 21 | `c5f443abb1834a4b3ce12b01378fd80b9b74f1d9221a035fe5ae1b79899c8b45` |
| `CLASS-STUDY.md` | 314,487 | 4,566 | 24 | `d597e099dea7b8a6977518f03c6253c586b59c8778691a7badefbf90ebf5cc3b` |
| `DEVELOPMENT-AUDIT-2026-09-15.md` | 101,440 | 1,690 | 50 | `e6dff5be5294dfef41f58dd71ba3a32a6afef7814fe9aecfb2f9367ffbf56e14` |
| `LAB-README-HISTORY.md` | 295,013 | 4,802 | 31 | `2b26cd8808c94498cf0a9a78747079ee60e6da508426b1598391b2e7e76d4641` |
| `LAB-README-2026-09-25.md` | 13,159 | 251 | 9 | `13c67a4f87417afa029920e059bfa6163a452a3752f3683d48b393df20ca483b` |

The original frozen 18 August body was independently extracted as source
lines 16–856 of `PROJECT-HISTORY.md`: 841 lines, 55,181 bytes and SHA-256
`168d191c288af5db4e76832c669fed96c27f5c41f8c8f8537751f05fc3941e5f`.
This reproduces its declared digest exactly.

## Portable products

| Product | Bytes | SHA-256 |
|---|---:|---|
| [Current historical ledger](../PROJECT-HISTORY.md) | 22,282 | `98f20f8a0c703c3e47279edb094bfeac5552368a076ef8f22780f97af3f5849a` |
| [Source map](../HISTORY-SOURCE-MAP.md) | 46,153 | `c036d42ff5778ac916863ee4aa1d6aa33e7a5afef04211fe0e47a3711d9f2e3e` |
| [Project ledger appendix](../history/PROJECT-LEDGER-THROUGH-2026-09-18.md) | 470,549 | `b8e058169c365479ab3bf7e9010d1a6d5ce7c9fd3ba32c22f330d6cfc0b7882d` |
| [Frozen ledger appendix](../history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md) | 68,439 | `b315de7db4b5272a64d0da13eab8d4b11a67c957011b31ae2ecd7b6ba2d78b66` |
| [Class-study appendix](../history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md) | 315,097 | `9ec03978e63d7eed1788c8e4d1ef8042ab8db8f9973b93180a837ed0169df28a` |
| [Development-audit appendix](DEVELOPMENT-AUDIT-2026-09-15.md) | 104,864 | `f265cd38d1b7bc96161fd7a15a06d74879cc082432ed3a4038f54330bb4381ca` |
| [Exhaustive Lab README appendix](../history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md) | 297,669 | `4c65e4c3b32731d933bf9197876bd71c5aa0e2a6e58a66eb147f86d69c1845fd` |
| [Concise Lab README appendix](../history/LAB-OPERATOR-README-2026-09-25.md) | 14,617 | `72d8ddafa1e021648fc6da599b9b0369a274cd1d2a3680a2f8202920e8b46ed0` |

## Coverage and reconstruction checks

The transformation was run twice consecutively from the same original bundle.
Every portable appendix and the source map reproduced the same SHA-256 on the
second run. The portable files are deliberately not byte-identical to the
originals: they add banners and anchors, retarget tracked links, render
unavailable evidence targets as inline paths, and apply the documented machine
identity substitutions. Exact original reconstruction therefore uses the
retained bundle member and its hash; portable-representation reconstruction
uses the transformation contract and per-heading mapping in the source map.

Section accounting closed exactly:

- an independent line-by-line comparison recovered 17,255 source lines in
  their original order, with zero missing lines; 16,835 lines were identical
  and all 420 differing lines reduced to equality after canonicalising only
  their Markdown-link representation;
- 182 Markdown headings were found outside fenced code across the six sources;
- 182 explicit source-line anchors occur in the six appendices;
- 182 source-block rows occur in the source map; and
- each source block begins at its original heading line and ends immediately
  before the next original heading, with the last block ending at EOF.

The transformation counters are recorded per file in the
[source map](../HISTORY-SOURCE-MAP.md). Its rows account for all original file
bytes and every section, not merely a selected narrative. The history ledger
then extends the record through v116 while separating scientific evidence,
engineering evidence and operational state.

## Portability checks

Validation parsed every ordinary relative Markdown link in `PROJECT.md`,
`README.md` and `docs/**/*.md`, resolved its target from the containing file,
and checked every supplied fragment against an explicit anchor or generated
heading slug. All targets and fragments resolved. Searches across the migrated
history found no machine home path, generated code-graph project identity or
Windows user-profile path. Evidence-only result/artifact locations are inline
code or route through the evidence index rather than broken clone-local links.

`git diff --check` passed for the historical ledger, source map, audit files
and appendices. Runtime code, schemas, configurations, receipts, results,
handoffs and checksum inventories were not modified by this documentation
migration. Separately reviewed native-architecture source changes are outside
this document-preservation audit.

## Retention decision

Keep the original source members byte-for-byte in the private migration bundle
and preserve their manifest. Commit only the portable documents. The
appendices and source map are frozen migration products; later status changes
belong in the current project ledger and dated additions to the historical
ledger.
