# Historical-document source map

This map proves coverage for the six workspace documents migrated on
25 September 2026. Original SHA-256 values identify the byte-exact files
held in the external migration bundle; portable-copy hashes identify the
tracked, sanitised appendices. The appendices are evidence-preserving
history, not present-status authority.

## Source inventory and transformation accounting

| Original source | Original bytes / lines | Original SHA-256 | Portable destination | Portable SHA-256 | Added anchors | Retargeted tracked links | Inlined evidence links | Machine identities replaced |
|---|---:|---|---|---|---:|---:|---:|---:|
| `PROJECT.md` | 470,494 / 4,917 | `36a9a72c40d01fb4453dd8479906dc010e2a0dd6c0e974984d776dd88531c150` | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md](history/PROJECT-LEDGER-THROUGH-2026-09-18.md) | `b8e058169c365479ab3bf7e9010d1a6d5ce7c9fd3ba32c22f330d6cfc0b7882d` | 47 | 32 | 188 | 0 |
| `PROJECT-HISTORY.md` | 66,625 / 1,029 | `c5f443abb1834a4b3ce12b01378fd80b9b74f1d9221a035fe5ae1b79899c8b45` | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md) | `b315de7db4b5272a64d0da13eab8d4b11a67c957011b31ae2ecd7b6ba2d78b66` | 21 | 4 | 11 | 0 |
| `CLASS-STUDY.md` | 314,487 / 4,566 | `d597e099dea7b8a6977518f03c6253c586b59c8778691a7badefbf90ebf5cc3b` | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md) | `9ec03978e63d7eed1788c8e4d1ef8042ab8db8f9973b93180a837ed0169df28a` | 24 | 7 | 101 | 0 |
| `DEVELOPMENT-AUDIT-2026-09-15.md` | 101,440 / 1,690 | `e6dff5be5294dfef41f58dd71ba3a32a6afef7814fe9aecfb2f9367ffbf56e14` | [audits/DEVELOPMENT-AUDIT-2026-09-15.md](audits/DEVELOPMENT-AUDIT-2026-09-15.md) | `f265cd38d1b7bc96161fd7a15a06d74879cc082432ed3a4038f54330bb4381ca` | 50 | 20 | 22 | 0 |
| `LAB-README-HISTORY.md` | 295,013 / 4,802 | `2b26cd8808c94498cf0a9a78747079ee60e6da508426b1598391b2e7e76d4641` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md) | `4c65e4c3b32731d933bf9197876bd71c5aa0e2a6e58a66eb147f86d69c1845fd` | 31 | 10 | 43 | 0 |
| `LAB-README-2026-09-25.md` | 13,159 / 251 | `13c67a4f87417afa029920e059bfa6163a452a3752f3683d48b393df20ca483b` | [history/LAB-OPERATOR-README-2026-09-25.md](history/LAB-OPERATOR-README-2026-09-25.md) | `72d8ddafa1e021648fc6da599b9b0369a274cd1d2a3680a2f8202920e8b46ed0` | 9 | 5 | 2 | 0 |

The original frozen ledger body is source lines 16–856 of
`PROJECT-HISTORY.md`, exactly 55,181 bytes with SHA-256
`168d191c288af5db4e76832c669fed96c27f5c41f8c8f8537751f05fc3941e5f`.
That digest remains the immutable identity of the 18 August snapshot;
the later continuation and migration banner are deliberately outside it.

## Portable transformation contract

The generator copied every source line in order and made only these
documented representational changes:

- a supersession banner was prepended to each destination;
- one stable `source-…-l…` HTML anchor was inserted immediately before
  each Markdown heading outside fenced code;
- links to tracked Lab files were made destination-relative, while
  cross-document historical links were directed to their matching
  portable appendix;
- links to ignored captures, receipts, caches, handoffs and external
  workspace-only inputs were converted to visible inline paths, because
  those objects are not guaranteed in a clean clone; and
- machine-specific home paths, Windows user-profile paths and generated
  code-graph project identifiers would be replaced by portable tokens.
  None occurred in these six source bytes, as the zero counts above show.

No narrative paragraph, table row, command, metric, cohort result or
receipt hash was intentionally summarised or deleted. The file-level rows
above cover all bytes; the heading-block tables below account for every
source section. A heading block runs from its heading through the line
immediately before the next Markdown heading, irrespective of nesting.
Lines that precede no later heading remain in the final block.

## `PROJECT.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–2 | 1 | QCSD thesis project ledger | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l1](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l1) |
| 3–75 | 2 | Current continuation — 18 September 2026, Australia/Sydney | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3) |
| 76–352 | 2 | Previous continuation — 17 September 2026, Australia/Sydney | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l76](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l76) |
| 353–354 | 2 | 1. Document contract and current status | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l353](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l353) |
| 355–368 | 3 | 1.1 Source-of-truth order | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l355](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l355) |
| 369–2419 | 3 | 1.2 Current implementation and evidence identity | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l369](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l369) |
| 2420–2450 | 3 | 1.3 Claim vocabulary | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2420](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2420) |
| 2451–2452 | 2 | 2. Research progression and principal outputs | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2451](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2451) |
| 2453–2484 | 3 | 2.1 Completed outputs | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2453](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2453) |
| 2485–2627 | 3 | 2.2 Compact milestone record | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2485](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2485) |
| 2628–2629 | 2 | 3. Architecture, threat model, and evidence flow | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2628](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2628) |
| 2630–2666 | 3 | 3.1 Repository and execution boundaries | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2630](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2630) |
| 2667–2692 | 3 | 3.2 Scientific and observer scope | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2667](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2667) |
| 2693–2714 | 2 | 4. Nine-mode defence inventory | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2693](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2693) |
| 2715–2716 | 2 | 5. Candidate implementation | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2715](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2715) |
| 2717–2745 | 3 | 5.1 Public interfaces and compatibility | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2717](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2717) |
| 2746–2847 | 3 | 5.2 Canonical BuFLO adaptation | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2746](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2746) |
| 2848–2917 | 3 | 5.3 Canonical CS-BuFLO adaptations | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2848](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2848) |
| 2918–3008 | 3 | 5.4 Shared action and evidence boundary | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2918](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l2918) |
| 3009–3010 | 2 | 6. Independent reference and original-study comparison | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3009](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3009) |
| 3011–3031 | 3 | 6.1 Pinned primary inputs | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3011](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3011) |
| 3032–3052 | 3 | 6.2 Oracle contract | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3032](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3032) |
| 3053–3068 | 3 | 6.3 Published BuFLO anchors | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3053](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3053) |
| 3069–3073 | 3 | 6.4 Published CS-BuFLO anchors | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3069](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3069) |
| 3074–3080 | 4 | Main 200-site study | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3074](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3074) |
| 3081–3087 | 4 | 120-site results | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3081](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3081) |
| 3088–3096 | 4 | 50-site early-termination ablation | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3088](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3088) |
| 3097–3123 | 3 | 6.5 Discrepancies and comparison discipline | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3097](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3097) |
| 3124–3125 | 2 | 7. Campaigns, evaluation, and evidence products | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3124](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3124) |
| 3126–3290 | 3 | 7.1 Prospective 100-class cohort | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3126](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3126) |
| 3291–3398 | 4 | Defence-failure repair contract | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3291](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3291) |
| 3399–3554 | 3 | 7.2 Staged matrices | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3399](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3399) |
| 3555–3623 | 3 | 7.3 Accepted-sample and handoff contracts | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3555](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3555) |
| 3624–3660 | 3 | 7.4 Correctness, performance, and attacks | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3624](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3624) |
| 3661–3662 | 2 | 8. Current candidate evidence and remaining gates | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3661](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3661) |
| 3663–3685 | 3 | 8.1 Older completed failed checkpoint: cohort v31 | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3663](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3663) |
| 3686–3833 | 3 | 8.2 V31 diagnosis and subsequent scheduler generations | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3686](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3686) |
| 3834–3858 | 3 | 8.3 Earlier candidate lineages | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3834](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3834) |
| 3859–4068 | 3 | 8.4 V32 failure and subsequent source resets | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3859](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l3859) |
| 4069–4113 | 3 | 8.5 V34 immutable failure and post-v34 scheduler correction | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4069](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4069) |
| 4114–4509 | 3 | 8.6 V36–v81 lineages and the current critical path | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4114](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4114) |
| 4510–4511 | 2 | 9. Canonical evidence index | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4510](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4510) |
| 4512–4527 | 3 | 9.1 Established and classifier evidence | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4512](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4512) |
| 4528–4545 | 3 | 9.2 Candidate parameters and references | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4528](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4528) |
| 4546–4601 | 3 | 9.3 Failed candidate checkpoints v27, v28, and v31 | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4546](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4546) |
| 4602–4896 | 3 | 9.4 V34–v81 lineage basis and current-source reset | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4602](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4602) |
| 4897–4917 | 3 | 9.5 Maintenance checklist | [history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4897](history/PROJECT-LEDGER-THROUGH-2026-09-18.md#source-project-md-l4897) |

## `PROJECT-HISTORY.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–15 | 1 | QCSD project ledger history | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l1](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l1) |
| 16–46 | 1 | QCSD thesis project ledger | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l16](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l16) |
| 47–61 | 2 | Workspace | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l47](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l47) |
| 62–133 | 2 | Provenance checkpoint | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l62](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l62) |
| 134–171 | 2 | Active workflow | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l134](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l134) |
| 172–183 | 2 | Profiles | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l172](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l172) |
| 184–199 | 2 | Defences and external inputs | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l184](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l184) |
| 200–261 | 2 | Workload catalogue and cohort freeze | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l200](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l200) |
| 262–512 | 2 | Active classifier POC cohort and response qualification | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l262](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l262) |
| 513–527 | 2 | Full-v2 qualification bindings for broader defences | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l513](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l513) |
| 528–567 | 2 | Fitting and sealed artifact bundle | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l528](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l528) |
| 568–710 | 2 | Research campaign sequence | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l568](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l568) |
| 711–755 | 2 | Authoritative result contract | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l711](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l711) |
| 756–829 | 2 | Completed research-readiness gates | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l756](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l756) |
| 830–859 | 2 | Future operational gates | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l830](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l830) |
| 860–865 | 2 | Historical continuation after the frozen snapshot | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l860](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l860) |
| 866–902 | 2 | 2026-08-19 to 2026-08-21 — sealed multi-origin classifier corpus | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l866](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l866) |
| 903–932 | 2 | 2026-08-27 to 2026-08-28 — BuFLO and CS-BuFLO candidate development | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l903](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l903) |
| 933–971 | 2 | 2026-08-28 — v20 reference, code, regression, and controlled result | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l933](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l933) |
| 972–1003 | 2 | 2026-08-28 — post-v20 correction and non-evidentiary v21/v22 attempts | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l972](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l972) |
| 1004–1029 | 2 | Next planned lineage — v23 | [history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l1004](history/FROZEN-PROJECT-LEDGER-THROUGH-2026-08-28.md#source-project-history-md-l1004) |

## `CLASS-STUDY.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–2 | 1 | QCSD 100-class final study methodology | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1) |
| 3–58 | 2 | Current continuation — 18 September 2026, Australia/Sydney | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3) |
| 59–298 | 2 | Previous continuation — 17 September 2026, Australia/Sydney | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l59](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l59) |
| 299–1704 | 2 | Earlier detailed protocol and checkpoint | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l299](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l299) |
| 1705–1750 | 2 | 1. Research purpose and claim boundary | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1705](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1705) |
| 1751–1752 | 2 | 2. Population and deterministic class selection | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1751](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1751) |
| 1753–1788 | 3 | 2.1 Pinned sampling frame | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1753](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1753) |
| 1789–2067 | 3 | 2.2 Exact page admission | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1789](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l1789) |
| 2068–2102 | 3 | 2.3 Longitudinal stability gate | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2068](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2068) |
| 2103–2186 | 3 | 2.4 Pilot, final cohort, and reserves | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2103](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2103) |
| 2187–2217 | 3 | 2.5 Mandatory selection and assembly receipts | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2187](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2187) |
| 2218–2367 | 3 | 2.6 Canonical fresh workspace layout | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2218](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2218) |
| 2368–2895 | 3 | 2.7 Foundation and acquisition bootstrap | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2368](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2368) |
| 2896–3785 | 3 | 2.8 Executable post-foundation runbook | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2896](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l2896) |
| 3786–3787 | 2 | 3. Modes and evidence roles | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3786](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3786) |
| 3788–3806 | 3 | 3.1 Compatibility and formal modes | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3788](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3788) |
| 3807–3825 | 3 | 3.2 Evidence-role isolation | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3807](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3807) |
| 3826–3871 | 2 | 4. Fitting and qualification pipeline | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3826](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3826) |
| 3872–3947 | 2 | 5. Admission sequence and matrices | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3872](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3872) |
| 3948–3976 | 3 | 5.1 Foundation, readiness, and pre-snapshot authorities | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3948](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3948) |
| 3977–4056 | 2 | 6. Compatibility and bounded-attempt semantics | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3977](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l3977) |
| 4057–4152 | 2 | 7. Formal acquisition and temporal evaluation | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4057](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4057) |
| 4153–4176 | 2 | 8. Historical guard, sealing, and promotion | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4153](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4153) |
| 4177–4566 | 2 | 9. Current prospective state | [history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4177](history/CLASS-STUDY-METHODOLOGY-THROUGH-2026-09-18.md#source-class-study-md-l4177) |

## `DEVELOPMENT-AUDIT-2026-09-15.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–4 | 1 | QCSD development and capture-readiness audit | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1) |
| 5–30 | 2 | Conclusion | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l5](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l5) |
| 31–66 | 2 | Interrupted run and current evidence | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l31](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l31) |
| 67–100 | 2 | What the 110-check suite spent time doing | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l67](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l67) |
| 101–102 | 2 | Ranked findings | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l101](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l101) |
| 103–138 | 3 | 1. Verification has test-execution side effects — must fix | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l103](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l103) |
| 139–161 | 3 | 2. Per-vector orchestration scales poorly — instrument and reduce | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l139](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l139) |
| 162–188 | 3 | 3. The changed DNS boundary has not been tested live — close the gap first | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l162](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l162) |
| 189–209 | 3 | 4. Acquisition scheduling can take a month — prospective protocol decision | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l189](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l189) |
| 210–242 | 3 | 5. All-600 completion and full-defence foundation block acquisition | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l210](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l210) |
| 243–268 | 3 | 6. Shutdown and monitoring need a bounded repair | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l243](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l243) |
| 269–299 | 2 | Actual remaining scale and ETA limits | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l269](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l269) |
| 300–322 | 2 | Recommended bounded next step | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l300](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l300) |
| 323–341 | 2 | Evidence hashes recorded during this audit | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l323](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l323) |
| 342–365 | 2 | Post-audit repair checkpoint — 15 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l342](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l342) |
| 366–389 | 3 | Separate execution from code-gate verification | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l366](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l366) |
| 390–417 | 3 | Previously skipped Chromium integration tests executed | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l390](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l390) |
| 418–464 | 3 | Selected DNS-prefetch control pair verified — 20:47 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l418](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l418) |
| 465–502 | 3 | Retained lifecycle transaction recovered — 20:50 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l465](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l465) |
| 503–550 | 3 | Approved prospective amendment — 22:00 AEST continuation | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l503](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l503) |
| 551–592 | 3 | Local validation and source freeze — 22:18 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l551](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l551) |
| 593–626 | 3 | Fresh v89 build completed and reverified — 22:35 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l593](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l593) |
| 627–651 | 3 | Goal resumed; v89 pinned CDP passed — 22:39 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l627](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l627) |
| 652–689 | 3 | V89 browser-egress qualification independently verified — 16 September 2026 AEST | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l652](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l652) |
| 690–727 | 3 | V89 acquisition-authority admission failed; receipt-consumer repairs underway — 03:53 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l690](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l690) |
| 728–767 | 3 | Receipt-consumer validation complete; clean source frozen — 04:12:55 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l728](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l728) |
| 768–815 | 3 | Fresh v90 build and pinned CDP completed — 04:30 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l768](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l768) |
| 816–857 | 3 | V90 interruption recovery audit — 17:53 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l816](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l816) |
| 858–899 | 3 | Cross-boot retirement diagnosis — 18:05 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l858](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l858) |
| 900–943 | 3 | Recovery and generic fix — 18:15 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l900](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l900) |
| 944–974 | 3 | Validation and source freeze — 18:28 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l944](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l944) |
| 975–1012 | 3 | V91 build verified — 18:47 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l975](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l975) |
| 1013–1049 | 3 | V91 browser gate independently verified — 23:57 AEST, 16 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1013](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1013) |
| 1050–1107 | 3 | V91 acquisition authority and initialisation — 00:13 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1050](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1050) |
| 1108–1152 | 3 | V91 first acquisition batch and teardown defect — 00:25 AEST, 17 September | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1108](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1108) |
| 1153–1215 | 3 | Acquisition browser repairs validated — 14:06 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1153](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1153) |
| 1216–1256 | 3 | Exact failed-acquisition archive — 14:16 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1216](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1216) |
| 1257–1284 | 3 | Policy-v15 source freeze — 14:19 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1257](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1257) |
| 1285–1316 | 3 | V92 build-retirement failure — 15:08 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1285](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1285) |
| 1317–1348 | 3 | V92 recovery and bounded repair — 15:15 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1317](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1317) |
| 1349–1372 | 3 | Timeout repair source freeze — 15:29 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1349](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1349) |
| 1373–1399 | 3 | V93 fresh build verified — 15:46 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1373](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1373) |
| 1400–1418 | 3 | V93 pinned-CDP verified — 15:49 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1400](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1400) |
| 1419–1455 | 3 | V93 interrupted after vector 32 — 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1419](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1419) |
| 1456–1501 | 3 | V93 recovery and identity-query repair — 17:39 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1456](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1456) |
| 1502–1547 | 3 | Identity-repair test interruption — 18:27 AEST, 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1502](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1502) |
| 1548–1577 | 3 | Fixture ownership and guardian census follow-up — 17 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1548](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1548) |
| 1578–1628 | 3 | Retirement phase measurement — 00:09 AEST, 18 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1578](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1578) |
| 1629–1660 | 3 | Complete repaired local regression — 00:24 AEST, 18 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1629](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1629) |
| 1661–1690 | 3 | Source freeze and live-Docker closure — 00:27 AEST, 18 September 2026 | [audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1661](audits/DEVELOPMENT-AUDIT-2026-09-15.md#source-development-audit-2026-09-15-md-l1661) |

## `LAB-README-HISTORY.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–15 | 1 | Archived QCSD Lab README | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l1](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l1) |
| 16–38 | 1 | QCSD lab | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l16](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l16) |
| 39–45 | 2 | Commands | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l39](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l39) |
| 46–2111 | 3 | BuFLO/CS-BuFLO candidate study | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l46](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l46) |
| 2112–2130 | 3 | Non-evidentiary ETF capability probe | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2112](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2112) |
| 2131–2533 | 3 | Prospective 100-class final campaign | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2131](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2131) |
| 2534–2739 | 4 | Fail-closed generational successor policy | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2534](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2534) |
| 2740–3043 | 3 | Retained focused candidate workflow — not the class-foundation bootstrap | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2740](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l2740) |
| 3044–3063 | 3 | `build` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3044](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3044) |
| 3064–3101 | 3 | `prepare` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3064](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3064) |
| 3102–3115 | 3 | `derive-chaff-prefix-specs` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3102](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3102) |
| 3116–3145 | 3 | `qualify-chaff` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3116](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3116) |
| 3146–3536 | 3 | `qualify-response-chaff` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3146](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3146) |
| 3537–3570 | 3 | `run` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3537](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3537) |
| 3571–3605 | 3 | `resume` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3571](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3571) |
| 3606–3632 | 3 | `verify` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3606](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3606) |
| 3633–3653 | 3 | `analyze` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3633](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3633) |
| 3654–3796 | 3 | Offline classifier-pilot handoff | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3654](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3654) |
| 3797–3825 | 3 | `fit` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3797](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3797) |
| 3826–3834 | 3 | `test` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3826](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3826) |
| 3835–3889 | 3 | `test pinned-cdp` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3835](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3835) |
| 3890–3920 | 3 | `test browser-egress` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3890](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3890) |
| 3921–3936 | 3 | `test live` | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3921](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3921) |
| 3937–3954 | 2 | Profiles | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3937](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3937) |
| 3955–4161 | 2 | Campaigns | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3955](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l3955) |
| 4162–4224 | 2 | Workload catalogue and research cohort | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4162](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4162) |
| 4225–4253 | 2 | Execution order and concurrency | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4225](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4225) |
| 4254–4371 | 2 | Result contract | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4254](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4254) |
| 4372–4419 | 2 | Capture, acceptance, and recovery | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4372](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4372) |
| 4420–4522 | 2 | Research readiness and five-class classifier proof of concept | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4420](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4420) |
| 4523–4802 | 3 | Fresh approved-origin multi-origin v2 cohort | [history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4523](history/LAB-README-ARCHIVE-THROUGH-2026-09-25.md#source-lab-readme-history-md-l4523) |

## `LAB-README-2026-09-25.md` section coverage

| Source block | Level | Source heading | Portable destination |
|---:|---:|---|---|
| 1–17 | 1 | QCSD Lab operator guide | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l1](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l1) |
| 18–40 | 2 | Current status | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l18](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l18) |
| 41–69 | 2 | Prerequisites | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l41](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l41) |
| 70–86 | 2 | Repository map | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l70](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l70) |
| 87–127 | 2 | Command surface | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l87](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l87) |
| 128–148 | 2 | Immutable execution rules | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l128](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l128) |
| 149–209 | 2 | Extended-class workflow | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l149](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l149) |
| 210–229 | 2 | Evidence and result handling | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l210](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l210) |
| 230–251 | 2 | Troubleshooting and safety | [history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l230](history/LAB-OPERATOR-README-2026-09-25.md#source-lab-readme-2026-09-25-md-l230) |

## Maintenance rule

These appendices and this map are frozen migration products. Future
status belongs in [PROJECT.md](../PROJECT.md), while new retrospective
analysis may be appended to [PROJECT-HISTORY.md](PROJECT-HISTORY.md)
without rewriting the mapped source bodies or their identities.
