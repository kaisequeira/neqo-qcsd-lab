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
| v130-image live diagnostics | `../diagnostic-acquisition-v130-20260930T1210Z/` and `../diagnostic-acquisition-v130-20260930T1232Z/` in the local sibling workspace | Non-evidentiary logs: root CDP interception failure, H3 site timeouts with passing controls, DNS failure and non-replayable egress. Retain for debugging; neither directory is a formal acquisition root or portable checkout dependency |
| v131 claim and interrupted build | `artifacts/buflo-study/cohort-claims-v1/claim-v131.json`; no verified v131 build receipt | Source `6f2861f4a316809cdd7b69be9fa3a13298d06ff9` was claimed, then its no-cache build was user-interrupted (exit 130). The version is consumed; there is no acquisition authority or accepted credit |
| v131 archived transaction | Host-local `artifacts/buflo-study/build-failure-v131/maintenance-receipt.json` (SHA-256 `d34f723d2523aed223dd4a778eb4472e03565b949176f501fe9044f9ed1cf153`) | The retained interrupted transaction was archived; this ignored operational receipt is not committed evidence or a build-success receipt |
| v132 blocked admission | `artifacts/buflo-study/cohort-claims-v1/claim-v132.json`; no build receipt | Claim consumed before Docker build when lifecycle admission found the unresolved v131 transaction; subsequent recovery passed, with no acquisition checkpoint or scientific credit |
| v133 provisional collection only | `artifacts/buflo-study/cohort-claims-v1/claim-v133.json`; host-local `artifacts/buflo-study/build-failure-v133/maintenance-receipt.json` (SHA-256 `29da91c9858c06867ca9ccf211e2209b0802ef54989f6a45a3fee62f83119ec2`) | Buildx completed 62/62 collection steps and produced provisional image `sha256:a1036e8e1b291e80e787f6d911430e711b3c5d4828b987dc6c75ef984aa2279a`. The post-export three-second image inspect timed out; no prepare/reference build, verified build receipt, authority or scientific credit. The ignored operational transaction was archived and recovery passed |
| v134 verified build | `artifacts/buflo-study/build-execution-v134.json` (SHA-256 `e168e0035c140edf70ffc76f41b912467aad5e4a62421ec6b2b39c547ee8b037`), `artifacts/buflo-study/build-completion-v134.json` (SHA-256 `f0916e27394ec507644ea0a280644cac7c3b2b162943baeba1c52935d87d7a8f`) | Independently verified no-cache collection, prepare and reference build on Lab `2d872257f89bc86bc1129c485d16dfcc1412d252` and Rust `2a9efa84ba0b81ca5d27d37fe2f8f73a08e2a91d`; collection image `sha256:1e302f4cb374da87e923194eff5cdc1720442f819985c6d1f7ed11a72032c79f`, prepare image `sha256:17c808803bec1a348c905e9005c00814a1ee8ccc61d0af6544b82b29dd361599` |
| v134 pinned CDP and acquisition-only authority | `artifacts/buflo-study/pinned-cdp-execution-v134.json` (SHA-256 `48f2a5021e8c32b2cd82a95df65a63b64cc0a9343872368a8dc6b9df9ec6a526`), `artifacts/class-study-acquisition-authority-v134.json` (SHA-256 `cbf29a098eac6b09c76ed66af885057ac7837c3d26d6bd3c6aff2159693cf5c7`) | Pinned CDP and the registered 16-file acquisition correctness suite passed on the v134 collection image; the three-gate schema-2 authority independently verified. It permits acquisition on that exact source but does not supply browser foundation, fitting or capture authority |
| v134 stopped bounded acquisition | `artifacts/classifier-multiorigin100-v1-acquisition-v134/` (checkpoint SHA-256 `e20d899f27a866a7828c1b065d2d4ca6936ea404be0b05e6ac89f72a4a044692`, provenance SHA-256 `f625f46dc7f5cb044a177bdbdf521c3ba4e68656e25ee59e6df9fc30c46a409a`) | One two-candidate watcher action stopped when `tranco-0000697` raised root `Fetch.continueRequest` `InvalidInterceptionId`; `tranco-0000984` recorded an H3 screen rejection. Both remain pending; no baseline, terminal receipt, accepted class or formal sample. Preserve the root and use a fresh cohort after source change |
| v135 failed collection build | `artifacts/buflo-study/cohort-claims-v1/claim-v135.json` (SHA-256 `d6b985a1d59775a06f3d81abb17788a1fec24ae7c55ebcff205f6bbe4ad36e44`); host-local `artifacts/buflo-study/build-failure-v135/buildkit.stderr.log` (SHA-256 `c90237539b5144377623bb388e5e790b63b98afb8a5f4cbb23b9cbc7d249a604`) and `archive-receipt.json` (SHA-256 `87e94196e6bee41403683a28f06429ebc09a1d9d5c6139ea3bb2cd3f5e4e4ebb`) | Rust code gate stopped on one synthetic exact-handoff timing test after 284 passed; no v135 image receipt, pinned CDP, authority, checkpoint or scientific credit. The two exact failed-build lifecycle roots were archived with unchanged v134 image tags, and public lifecycle recovery passed. The claim is consumed and the ignored operational archive cannot authorize source or version reuse |
| v136 failed collection build | `artifacts/buflo-study/cohort-claims-v1/claim-v136.json` (SHA-256 `3766645b9cacdde83438b8403808d3ed444e650edba659c4a9be083cb3a5cd45`); host-local `artifacts/buflo-study/build-failure-v136/buildkit.stderr.log` (SHA-256 `f07cf6175a39f50061340c64431378f23faa529ba5400856f49ef033aa9e649a`) and `archive-receipt.json` (SHA-256 `2ee0da97a45cd177a410632e4700b25b642da303cbf9fe51125efe5b2de40f7f`) | Rust code gate passed 284 tests and rejected the test-only five-second deadline as outside the nominal strict window. No v136 image receipt, pinned CDP, authority, checkpoint or scientific credit. The exact failed-build lifecycle roots were archived with unchanged v134 image tags, public lifecycle recovery passed, and the claim remains consumed |
| v134 live root CDP reproduction | Host-local `../diagnostic-rehearsals/v134-root-late-network-20261001-1/events.jsonl` (SHA-256 `1f9b6e697d4361b21f2348ec1b5b4e12311e339d368489e37ec5cdaea5d6d789`) | Zero-credit two-worker navigation-only diagnostic in the v134 prepare image reproduced the pinned exception on two root Font requests. Sanitized events show `Fetch.requestPaused` before matching `Network.requestWillBeSent`; this diagnostic is not an acquisition terminal or source-bound authority |
| Proposed retry live check | Host-local `../diagnostic-rehearsals/v134-proposed-root-retry-20261001-1/run/events.jsonl` (SHA-256 `9c74f9932b7b8c42fd1a3f2460829089fa915edba7620e5577c34d2d6d5231ee`) | Zero-credit two-worker navigation in the v134 prepare image reached a distinct root Font Fetch-only `InvalidInterceptionId`: the matching Network start or terminal never appeared. The strict late-Network guard failed closed. One other candidate navigated. No formal checkpoint or scientific numerator changed |
| Revised retry live checks | Host-local `../diagnostic-rehearsals/v134-proposed-unpaired-retry-20261001-1/run/events.jsonl` (SHA-256 `5142bd8e92b4da462f282acfb8251839430a41e7598b50d4aae42c6958b10771`) and `../diagnostic-rehearsals/v134-proposed-single-nav-20261001-1/run/events.jsonl` (SHA-256 `be1305b17665b7e259c14bb430f1f4cb07766fb8b3949808dcc59a84c3d2c54c`) | In the revised two-worker check, one candidate navigated and the other hit an exact late-Network Font fault, which was discarded after cleanup and classified recoverable; the diagnostic exits incomplete because it does not perform coordinator retries. A fresh single-worker check of that candidate navigated in 33 seconds. These are zero-credit checks with mounted proposed source; no formal root changed |
| Prebuild acquisition rehearsals | `../diagnostic-rehearsals/` in the local sibling workspace | Create-only, zero-credit host/container/live diagnostics, including the control-bracketed 600-root survey, failed attempts, one complete two-origin prepared catalogue graph, and local capture checks. Not a portable checkout dependency, formal acquisition root, or authority receipt; the [rehearsal report](ACQUISITION-REHEARSAL.md) records exact counts and limits |
| Current-client Zoomlife diagnostic | `../diagnostic-rehearsals/zoomlife-schema12-directional-20261001-1/` in the local sibling workspace | Zero-credit exact-page H3 screen, 63-resource two-origin deep-validated schema-2 preparation, five-request schema-4 and 40-request schema-5 Rust response receipts. The receipt-consumer check bypassed only the diagnostic binary's `migration_commit="unknown"` provenance format; it is not formal qualification or a portable checkout dependency |
| Current-client capture diagnostics | `../diagnostic-rehearsals/zoomlife-new-client-capture-20261001-1/` in the local sibling workspace | Zero-credit public Zoomlife sealed incomplete capture after its main document changed; local two-origin `local-seal-2` accepted and deep-verified 2/2 undefended samples with source cleanliness recorded as unknown. FRONT/Tamaraw and Walkie-Talkie local wire tests passed with the diagnostic provenance parser substitution. `local-vertical-1` preserved a second-origin prefix failure. After the scoped schema-4 fix, `local-vertical-2` passed three response and three prefix qualification waves, then accepted and deep-verified a two-origin FRONT sample. `local-wt-1` consumed its exact full prefix sidecar and sealed 1/1 accepted. After the shared Rust HTTPS-origin fix, the rebuilt client repeated this as `local-vertical-3` and directly linked `local-wt-2`, both 1/1 accepted. The latest packet test invocation passed FRONT/Tamaraw and Walkie-Talkie; its broader capture test deep-verified and then failed a formal clean-source assertion against unknown diagnostic provenance. The unpatched verifier rejects unknown/dirty diagnostic provenance as expected. `local-seal-1` inherited stale v130 metadata and has a separate invalid-for-authority note; preserve it but never cite it as source-bound evidence |
| Prospective HTTP/3 screen | New source-bound acquisition checkpoint, once executed | Schema-12 pre-baseline controls and exact selected-page URL outcomes belong in the hash-bound navigation-attempt ledger; historical schema-11 receipts remain verify-only and no v129 classification is replaced |
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
