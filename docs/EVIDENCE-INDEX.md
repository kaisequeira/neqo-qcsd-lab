# Evidence locations and retention

Migration policy: 25 September 2026. Paths below are relative to the Lab
repository unless explicitly described as migration-bundle items. Local
evidence is deliberately written as code paths, not Markdown links: it is
not present in every clone. The [project ledger](../PROJECT.md),
[runbook](CLASS-STUDY.md), [history](PROJECT-HISTORY.md) and
[historical source map](HISTORY-SOURCE-MAP.md) are tracked and portable.

## Desktop working set

| Evidence | Relative location | Why it travels |
|---|---|---|
| Protected five-class handoff | `handoffs/classifier-multiorigin5-v2/` | Complete sealed 2,500-sample historical guard; verify all 12,503 `SHA256SUMS` entries |
| All existing artifacts | `artifacts/` | Build/reference/code receipts, browser checkpoints, allocation history, fitting inputs and provenance |
| Historical fitted parameter bundle | `artifacts/research-1200/` | Existing cohort's fitted parameters; included within all artifacts, not a substitute for new class fitting |
| Pinned independent reference input | `artifacts/buflo-study-reference-input-v1/` and its checksum inventory | Papers, author/archive inputs and reference execution dependencies |
| v116 browser evidence | `artifacts/buflo-study/browser-egress-qualification-v116/` | Incomplete laptop checkpoint and retained passing/failing attempts; no desktop execution authority |
| v124 native build and pinned CDP | `artifacts/buflo-study/build-execution-v124.json`, `artifacts/buflo-study/build-completion-v124.json`, `artifacts/buflo-study/pinned-cdp-execution-v124.json` | Verified desktop prerequisites bound to the v124 source; no browser or acquisition authority |
| v124 browser evidence | `artifacts/buflo-study/browser-egress-qualification-v124/` | Valid open inventory with 28 passing vectors and a sealed operational failure on vector 29; no final receipt |
| v124 ETF diagnostics | `artifacts/buflo-study/etf-probe-engineering-v124.json`, `artifacts/buflo-study/etf-veth-probe-2048-v124/`, `artifacts/buflo-study/etf-veth-probe-2048-v124-r1/`, `artifacts/buflo-study/etf-veth-probe-2048-v124-r2/` | Capability probe passed; three large timing/clock diagnostics incomplete and non-evidentiary |
| v129 build and pinned CDP | `artifacts/buflo-study/build-execution-v129.json`, `artifacts/buflo-study/build-completion-v129.json`, `artifacts/buflo-study/pinned-cdp-execution-v129.json` | Independently verified clean-source no-cache build and pinned-CDP gate; bound to v129 only |
| v129 browser qualification | `artifacts/buflo-study/browser-egress-qualification-v129/` | Independently verified final 110/110 with zero operational or semantic failures; bound to v129 only |
| v129 acquisition-only authority | `artifacts/class-study-acquisition-authority-v129.json` | Independently verified four hard gates without waivers; permits public-page acquisition on v129, not later defence capture |
| v129 failed acquisition | `artifacts/classifier-multiorigin100-v1-acquisition-v129/` | Initialized checkpoint, retained attempts and terminal evidence; `tranco-0000697` missed its probe window, and `tranco-0000984` has a durable internal redirect dependency error; zero accepted classes |
| v130 build and pinned CDP | `artifacts/buflo-study/build-execution-v130.json`, `artifacts/buflo-study/build-completion-v130.json`, `artifacts/buflo-study/pinned-cdp-execution-v130.json` | Independently verified on the v130 source; cannot authorize corrected source |
| v130 browser qualification | `artifacts/buflo-study/browser-egress-qualification-v130/` | Independently verified final 110/110 on the v130 source |
| v130 authority attempt | No authority receipt was issued | Creation-time correctness failed on a watcher test-list mismatch and missing user-systemd runtime in the qualification container; the failure is recorded in the project ledger |
| Prospective HTTP/3 screen | New source-bound acquisition checkpoint, once executed | Schema-11 pre-baseline control and selected-page request-origin outcomes belong in the hash-bound navigation-attempt ledger; no v129 receipt or classification is replaced |
| Original ledgers, papers and unique local research files | Original relative paths recorded in migration manifest | Thesis sources and lossless documentation provenance |
| Source backups and operational continuation | Git bundles and uncommitted migration handoff | Local/legacy revisions, published commit identities, transfer checksums and machine-specific recovery context |

Git supplies source, versioned configuration and tracked documentation. Restore
the local working set into its original relative layout. Do not rewrite old
receipt paths, hashes or provenance for the desktop. A historical receipt
whose referenced raw campaign remains on the laptop may require that campaign
for a full audit; copying the receipt does not make its dependencies portable.
The standalone v129-image diagnostic that reached the `cloudflare-quic.com`
Neqo control but timed out on `consultant.ru` and `www.consultant.ru` has no
formal receipt. It is an engineering observation, not a scientific terminal or
authority to resume or reclassify the v129 checkpoint.
The desktop's private `migration-2026-09-25/inventories/desktop-handoff-verification.json`
records the new 12,503-entry protected-handoff check. Keep it with the
downloaded transfer manifests outside Git.

The tracked curated-source receipt is
[`config/curated-sources/crux-73-v1.source.json`](../config/curated-sources/crux-73-v1.source.json).
It binds the user-supplied 73-domain file by SHA-256 and preserves source-order
domains and compact origin hints. It is input provenance, not an acquisition
receipt or authority for the registered study.

## Laptop research archive

| Evidence family | Relative location | Retained purpose |
|---|---|---|
| Original v2 classifier campaigns | `results/research-classifier-multiorigin5-v2-*` | Source capture audit, failures, resume history and exporter regeneration |
| Earlier classifier experiments | Other `results/research-classifier-*` | Earlier population/transport experiments and reasons for supersession |
| Historical fitting/smoke | `results/research-fitting-1200/`, `results/research-smoke-1200/`, `results/consolidated-smoke/` | Evidence behind established fitting and smoke milestones |
| BuFLO/CS-BuFLO regression | `results/buflo-study-regression-v*/` | Per-cohort runtime/timing failures, fixes and completed regression gates |
| BuFLO/CS-BuFLO controlled runs | `results/buflo-study-controlled-v*/` | Network-conditioned correctness/fidelity and qualification progression |
| Other diagnostic/result trees | Remaining `results/` and older `handoffs/` | Supporting development evidence; see exact laptop inventory |

The migration bundle contains the exact relative file inventory, byte sizes
and SHA-256 hashes for laptop-only evidence. Wildcards above describe families;
they are not an instruction to move, delete or reclassify a cohort. Retrieve a
complete required result root and verify its closed inventory when a later
audit needs original raw evidence. The current historical guard reads the
sealed classifier handoff; ordinary desktop continuation does not require its
original result directories.

Keep the laptop's evidence intact through thesis submission. Preserve failed
attempts and complete checksum inventories even when their cohort has been
superseded. The record of a failure explains the design decision; it is not a
passing qualification on later source.

## Regenerated material and verification

Rust targets, virtual environments, ordinary caches, code-graph indexes and
Docker images/containers/volumes are regenerated. Existing sessions and
credentials do not belong in the transfer. Legacy repository working trees
are excluded from active development; preserve relevant Git revisions in the
bundles before any later cleanup.

The private migration handoff records the actual Drive folder/part links,
archive member paths, source heads and restoration commands. Verify every
archive-part hash before extraction and every restored-file hash afterwards.
Then deep-verify the protected handoff and recalculate its five-class counts:
2,500 total, 1,500 undefended, 500 FRONT and 500 Tamaraw. Verify all source
bundles and the Lab Rust Gitlink as well.

Do not commit raw results, archives, credentials or machine-specific transfer
instructions. Add new milestone references here and measurements/decisions to
the tracked history; record accepted current counts in the project ledger.
