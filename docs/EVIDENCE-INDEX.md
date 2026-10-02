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
| v138 verified build | `artifacts/buflo-study/build-execution-v138.json` (SHA-256 `443f229b9d4346359fb0802f5fff7d8c06c3495264435641ee00ec1c399aa7d7`), `artifacts/buflo-study/build-completion-v138.json` (SHA-256 `a6f1541965ddc3fd7d266f95e2a514bcaea848220282d195248af696b33a26ef`) | Independently verified no-cache collection, prepare and reference build on clean Lab `6f77041680ac37708be2c2174989f127db285c09` and Rust Gitlink `a8d8664cd31cbc4cc1ecb4fd5abc5a1d3ee153ae` |
| v138 pinned CDP and acquisition-only authority | `artifacts/buflo-study/pinned-cdp-execution-v138.json` (SHA-256 `8c4223cce50cb15f32ca8ae88a7a77b9fd91d8883ab17cd3c02b6570285617a7`), `artifacts/class-study-acquisition-authority-v138.json` (SHA-256 `641885a87bea16c906195cedcd5d8750d8483f23f0310007751b95d101672e21`) | Pinned CDP and acquisition-focused correctness passed; no-waiver schema-2 authority independently verified for public-page acquisition on v138 only. The 110-vector browser gate and full defence foundation did not run on this source |
| v138 blocked bounded acquisition | `artifacts/classifier-multiorigin100-v1-acquisition-v138/` | Initialized frozen 600-candidate checkpoint and two supervised watcher actions produced four candidate terminal records: `tranco-0000697` and `tranco-0000984` HTTP/3 site-policy rejections; `tranco-0000553` non-replayable WebRTC egress site-policy rejection; `tranco-0000837` three recoverable DNS failures and immutable pre-probe blocker in the first stratum. No accepted pilot class or formal sample. Any prospective DNS-rule change requires a fresh source cohort; v138 remains historical |
| v139 build and early acquisition authority | `artifacts/buflo-study/build-execution-v139.json` (SHA-256 `5e21aa120e6aa1081f98b3096f6cc40a3369bbe8f368c3f931ee18cb885709c9`), `artifacts/buflo-study/build-completion-v139.json` (SHA-256 `b089b77ff5a239c3e95967f49002126a773fbb2c42145e1cca038a199de3e662`), `artifacts/buflo-study/pinned-cdp-execution-v139.json` (SHA-256 `868b2d4a06e2f837442bee8bae2bec3bfc07445040368543cfd6eb837e826b1e`), `artifacts/class-study-acquisition-authority-v139.json` (SHA-256 `00de9421076f8d2a9211aa2d7ebd1aa9da43e07b56562c3100c0a2947d18e148`) | Bound to clean Lab `34088bb687ec683f16597da41e2c02a11f201447` and pinned Rust `a8d8664cd31cbc4cc1ecb4fd5abc5a1d3ee153ae`; permits public-page acquisition on v139 only. Same-source 110-vector browser qualification and full defence foundation have not run |
| v139 stopped acquisition | `artifacts/classifier-multiorigin100-v1-acquisition-v139/` (checkpoint SHA-256 `af6f6b5afeb31ce42e1db4b3d7d245bdd4b6862b443df1fa4b94c13a2929bd5b`, provenance SHA-256 `016d5bf81c59e9bef9acb113ea93a03290c6a1242fdbdd3979c5a7824761d72c`) | Eight immutable site-rejection terminals; `tranco-0000709` remains pending after an inconclusive HTTP/3 screen; `tranco-0000280` has a durable internal `Fetch.failRequest` browser-control error. The read-only checkpoint validator rejects completion, and no pilot or formal sample was accepted. Preserve all attempts; changed source requires a new cohort |
| v140 build and pinned CDP | `artifacts/buflo-study/build-execution-v140.json` (SHA-256 `f4bda5f06cac174277720968f72cbadaf05ce07bf39128881f00f3e827993cd6`), `artifacts/buflo-study/build-completion-v140.json` (SHA-256 `affa26e2fc6e4e1aa83e157c92877c3f21f127138e57bae9050092fb068d1265`), `artifacts/buflo-study/pinned-cdp-execution-v140.json` (SHA-256 `9c73ebc783c3c8ad0cca3982a06558100cac9d1c0af8aa4e4c99be894218e940`) | No-cache build and pinned-CDP check passed on Lab `0535198a7af59039337b5760b6997e8192c3adb6` and Rust `a8d8664cd31cbc4cc1ecb4fd5abc5a1d3ee153ae`; these receipts do not authorize changed source |
| v140 20-site authority failure | No authority receipt was issued | The installed Python package sought the 20-site overlay beneath its virtual environment instead of the mounted Lab source. The command exited 1 before acquisition initialization; there is no v140 20-site checkpoint or accepted pilot |
| v141 failed preparation build | `artifacts/buflo-study/cohort-claims-v1/claim-v141.json` (SHA-256 `ee04663c6afbae7fdd1ab27a0c07c870d961afb7de840fdc31ac0429538f5d0b`); no paired build receipts | The collection image completed, then one exact-handoff Rust test failed after 284 passed in the no-cache preparation image. BuildKit retained local histories `16frqb99orecnr5q882cwag14` (collection) and `4j4hy4y94sdcax8dbe1cwdezb` (preparation). This consumed v141 without pinned-CDP, 20-site authority, acquisition checkpoint or scientific credit |
| v141 failed-build archive | Host-local `artifacts/buflo-study/build-failure-v141/archive-receipt.json` (SHA-256 `9cc41ee35ba1bfccf12835fe2dcbf8c622ae789db6b94eb2b249a530a53058ea`) and sibling BuildKit logs | Exact failed-build lifecycle roots and the provisional v141 collection image were hash-audited and preserved without granting authority or version reuse. The active lifecycle namespace was empty and public `lifecycle-recover` passed before v142 |
| v142 build and pinned CDP | `artifacts/buflo-study/build-execution-v142.json` (SHA-256 `ee22393e2d3a6e69e2eb72cf0abf4a3a19504a9b34ef2b2da17abf01015a432e`), `artifacts/buflo-study/build-completion-v142.json` (SHA-256 `c8115ac1450fc81becf3565c47fd726d7cd655423c4ca36011306858596a4dda`), `artifacts/buflo-study/pinned-cdp-execution-v142.json` (SHA-256 `e505c5fc642c246877b3a032e07ea42325aaa4428bf7aaf2e2b31540815e5717`) | Independently validated no-cache build and passing browser-control check on clean Lab `f2f46716a76f0e8888420a3e57e0d551a341e65b` and Rust `ca70e626275fb3dfb4520696568e7b2ad800174f`. These remain valid for v142 source only |
| v142 20-site authority failure | No authority receipt was issued | The 20-site acquisition correctness suite passed 2,522 tests, failed three stale test fixtures and skipped 31. The command exited 1 before acquisition initialization; no v142 20-site checkpoint, pilot or formal sample was accepted. Preserve the v142 build and pinned-CDP receipts without treating them as search or capture approval |
| v143 build and pinned CDP | `artifacts/buflo-study/build-execution-v143.json` (SHA-256 `dcbb844fa6fc8b24f8ec9c23687316cf159b709d4feb26c7daf108240e8ab2c1`), `artifacts/buflo-study/build-completion-v143.json` (SHA-256 `cee3c8945fbea7c99f2204dd8395ec3a1ce900be176c2dc1aeb412ae0405fc49`), `artifacts/buflo-study/pinned-cdp-execution-v143.json` (SHA-256 `80fe6d63bbad2dd255e917470d9dcc85d7e91afda8f0740b9b65252887d09196`) | No-cache three-image build and pinned-CDP probe passed on clean Lab `032c5767f398aeec9e0d5c51bc3a12257ec9bff9` and pinned Rust `ca70e626275fb3dfb4520696568e7b2ad800174f`; these receipts are source-bound to v143 |
| v143 issued 20-site acquisition-only authority | `artifacts/classifier-multiorigin20-v1-acquisition-authority-v143.json` (SHA-256 `e74c4fcbdd9bc12b325872eb7b95cea47f5a196dd7e301a6ed1428f965e85530`) | The in-image creation check passed after the acquisition suite reported 2,525 passed and 31 skipped (2,556 collected). Public host verification stopped before Docker because raw `/lab/config/...` receipt paths differed from host absolute paths despite matching file hashes. `acquisition-init` uses the same host admission, so no 20-site acquisition root, pilot or formal sample was issued. A portable validator repair is prepared in this source revision and needs fresh clean-source reproof; v143 cannot authorize changed source or later defence capture |
| v144 failed preparation build | `artifacts/buflo-study/cohort-claims-v1/claim-v144.json` (SHA-256 `918795c374148b004023185ee572fbd98b9b476fd2cb6c2fdb844597ff9753d8`); host-local `artifacts/buflo-study/build-failure-v144/buildkit-collection.stderr.log` (SHA-256 `a4aa1205252496096d78fe330ab5febc5b34bf256ab1decf158d456f05b36f6b`) and `buildkit-prepare.stderr.log` (SHA-256 `c9e49ded95aa87207c9cc69d3cd3e9c1a51db7183a975cdfcca967c57c8da09a`) | Clean Lab `62d7dc66db65bc2f157d08a0e638a05f27c6e6b4` and pinned Rust `ca70e626275fb3dfb4520696568e7b2ad800174f`: no-cache collection history `0mooo9ddxrc8dtuit7dbd55xa` completed, preparation history `bqvye8sz2gqe54jfd9up1inmx` failed one exact-handoff test after 284 passed. No paired build receipts, pinned CDP, 20-site authority, checkpoint or scientific credit; v144 is consumed |
| v144 failed-build archive | Host-local `artifacts/buflo-study/build-failure-v144/archive-receipt.json` (SHA-256 `a29f61d0c052c3fc12def424c4ddcb752d50a1953c56f7bc54ca55e482588581`) and `inventory.json` (SHA-256 `ebc8f8bf2f49e4fe88643f32f062de1cd5508f5ef37ca019776b3006cefa8b0b`) | The two exact lifecycle roots were hash-audited, moved under exclusive lock into `retired-lifecycle/`, and checked against their staged snapshots; only those roots moved. The active lifecycle namespace is empty and public `lifecycle-recover` passed. The collection image remains provisional; this ignored operational archive grants no authority or version reuse |
| Post-v144 Rust timing diagnostic | Host-local `artifacts/buflo-study/build-failure-v144/rust-diagnostic.log` (SHA-256 `260d594fdfb3c32a647d7bc9371f96504d6e03165459a7e2448fe9295c8b1673`) | Pinned Rust 1.90/NSS toolchain, read-only mounted corrected source: `cargo fmt --check`, all three focused timing cases, and the full 285/285 `neqo-bin` suite passed. This is zero-credit engineering verification of an uncommitted correction, not a v144 repair or a substitute for a fresh no-cache build |
| v145 build and pinned CDP | `artifacts/buflo-study/build-execution-v145.json` (SHA-256 `515d8a4609d4a86d69f70252404c40a0184b8a7bcb56212baf628dc5cecaa05d`), `artifacts/buflo-study/build-completion-v145.json` (SHA-256 `e32bc857277965796c527afb4d9508a8b815e26ccfd3c5956db36ace46f98e1d`), `artifacts/buflo-study/pinned-cdp-execution-v145.json` (SHA-256 `0f40aa4d3228294c588e6970bacb85345fff609916caf97f81f7076f481faaec`) | No-cache three-image build and pinned-CDP probe passed on clean Lab `8309fa38bf711f80fdf88e6612fbcd8dade991bd` and Rust Gitlink `acc2c6ae8ef2a12be582dd7e1af0dc3817040fd5`; these receipts remain bound to v145 source |
| v145 issued 20-site acquisition-only authority | `artifacts/classifier-multiorigin20-v1-acquisition-authority-v145.json` (SHA-256 `5776d054b9bc0af1b1dd596231cae77905c364178aa63d35c2c4d17b95e5d5cf`) | In-image creation validation passed after 2,528 acquisition correctness tests passed and 31 skipped. Separate public `class-study verify` rejected the receipt because the v145 target-type allowlist omitted acquisition authority. A corrected router passed focused tests and a read-only check against the real receipt in the collection image; the initializer's authority validator and binding passed in the preparation image. These checks grant no v145 authority. No v145 acquisition root, accepted pilot or formal sample was issued. Preserve the failed verification; the changed-source correction needs fresh cohort proof |
| v146 clean build and browser check | `artifacts/buflo-study/build-execution-v146.json` (SHA-256 `1cf35afc2a0f88791371b51e8b2abb13a9a4afc49b6606fd38590e11ef546063`), `artifacts/buflo-study/build-completion-v146.json` (SHA-256 `58f0ff8b1de872e6a0301f3c33f491104d3abceb18ca054e3cf1dac5dddc13d3`), `artifacts/buflo-study/pinned-cdp-execution-v146.json` (SHA-256 `488f0da3bdfed05112acfbd8ae92dd99dc9564e9e9462fc476701889db1f4f42`) | Three-image no-cache build and pinned browser-control probe passed on clean Lab `2194a71055cb35c84514cebaf594b6d99241ebf4` and Rust `acc2c6ae8ef2a12be582dd7e1af0dc3817040fd5`; the build receipt independently validated for v146 |
| v146 20-site acquisition authority | `artifacts/classifier-multiorigin20-v1-acquisition-authority-v146.json` (SHA-256 `1b264bea7c01f6a9550d6e422ac7198395a1b1fa8050ece30fd71ec6aece6fe1`) | Acquisition correctness passed 2,528 tests and skipped 31; public `class-study verify --study-id classifier-multiorigin20-v1` passed and acquisition initialization succeeded. Scope is public-page acquisition only, with no fitting or capture authority |
| v146 initialized root and blocked watcher | `artifacts/classifier-multiorigin20-v1-acquisition-v146/provenance.json` (SHA-256 `51afa156751f222d7afa0e491a74ec412486c89b0d5eb70de16201b03a524dfd`), `checkpoint.json` (SHA-256 `555d21d4411af720f8fd1078e185f426ec960dcccddce49ce8a067494dee7614`), and its three `terminals/` receipts | Three bounded watcher actions attempted four candidates. `tranco-0000697` and `tranco-0009491` are scientific site rejections. `tranco-0067760` terminalised after three inconclusive screens: all 30 selected-page probes returned peer TLS handshake failure while controls passed; its disposition is selection-blocked. `tranco-0204878` passed prebaseline screening but all four first timed probes logged a durable `CdpTargetIntegrityError` for an unmatched loading terminal; read-only acquisition status now refuses the checkpoint. No 20-site pilot or formal recording was accepted; preserve this root unchanged |
| v146 browser fault and proposed-source rehearsal | Host-local `../diagnostic-rehearsals/v146-cdp-orphan-20261002-1/four-page-lifecycle.log` (SHA-256 `248b89426a215d18d82d462e38e2e266beb37a7a51f6290b1bee91a780101393`) and `../diagnostic-rehearsals/v147-cdp-source-mount-20261002-1/run.log` (SHA-256 `9040f4af5c351fafadad5ec8e11734e0309e04f5a6a7662ddfe826b8d32155ac`) | Zero-credit four-page replay reproduced the v146 orphan. Each request ID matched an active `about:srcdoc` Page loader with a 15-byte finish. The proposed source then completed all four page discoveries and accepted 12 loader-bound 15-byte finishes. This does not prove later acquisition or give v146 credit |
| v146 authority historical replay | Host-local `../diagnostic-rehearsals/v147-cdp-source-mount-20261002-1/historical-authority.log` (SHA-256 `555351551b3685348e0c684d8306726a633cd293a967bb6652c5f9d77b36e2d7`) | Read-only prepare-image check using proposed source independently reconstructed the exact v146 20-site acquisition authority as historical verify-only; it cannot authorize a new cohort |
| v147 clean build and browser check | `artifacts/buflo-study/build-execution-v147.json` (SHA-256 `12794cc545c0b60607d7a4cd0204744ee555a87ebf29e5931912f5a14a7c85a1`), `artifacts/buflo-study/build-completion-v147.json` (SHA-256 `d141fdf5c077a7cd388596868ad0c1a0c13a0bf296b72e3f4517c2b16b73b731`), `artifacts/buflo-study/pinned-cdp-execution-v147.json` (SHA-256 `4c0293b389a1efcfe17d69032eb3d1aaa1fee39cee553847fa99fec82f83cef1`) | Three-image no-cache build and pinned browser-control probe passed on clean Lab `610db9cc04082bbc952148ff1d87e25636a6e75a` and pinned Rust `acc2c6ae8ef2a12be582dd7e1af0dc3817040fd5`; no site-search authority followed |
| v147 site-search qualification failure | `artifacts/buflo-study/cohort-claims-v1/claim-v147.json` (SHA-256 `f057abd61b40bdf54920338d5d37bb1fa20f3d80ca9ee6aea08c3fd4077a6f4f`); no `artifacts/classifier-multiorigin20-v1-acquisition-authority-v147.json` exists | The source-bound acquisition correctness suite reported 2,537 passed, three failed and 31 skipped. Three stale historical test fixtures used current schema/policy values after the schema-14 amendment. The command exited 1 without an authority receipt or acquisition root. v147 is consumed, with no new pilot or formal recording |
| v148 user-stopped obsolete build | `artifacts/buflo-study/cohort-claims-v1/claim-v148.json` (SHA-256 `e4220f7c00451f93e365da4a2fd21de3b1cd6ae33f6c8c40114f73f55b416f1c`); host-local `artifacts/buflo-study/build-failure-v148/archive-receipt.json` (SHA-256 `bb676c8fe2a0119393697f5ca2f6c94b1aa1eadb22453b9c8e7da775acc46f94`) | The 20-site build was interrupted after the study scope changed. Its exact lifecycle roots and claim were archived, recovery passed, and v147 image tags remained unchanged. No v148 build-success pair or scientific authority exists |
| v147 multi-origin capture rehearsal | Host-local `../rapid-execution-v147/results/rapid-preflight-multiorigin-baseline-001/20261002T092025.465255Z/` (`evidence.sha256` SHA-256 `3f59b3f3e75d4de5b069c3ec4587de86e2117b4b35474269e18bcdc43b18087a`) | A one-visit, three-origin baseline campaign completed in the unchanged v147 collection image; public `qcsd-lab verify` reported complete, 1/1 accepted and nine authoritative files. Zero rapid-study or formal credit |
| Curated root HTTP/3 survey | Host-local `../diagnostic-rehearsals/curated-h3-20261002/` with three create-only JSONL logs (SHA-256 `5789f8324be30a886b752069603e2238e504b68aee8639c92b5f699e62df1ba5`, `ffb4eacb9ce914b847f073d2821154a71bd2a3f2bd2449daa26c3387fe1ca82a`, `85a12896fb1682067c7d652ba070d08e6efbba5f9f6aeaee4b58dbf2f92c49e1`) | Eight control pairs passed; of 66 unflagged homepage probes, 30 were clearly H3 valid, 28 ambiguous, six peer `296` closes and two timeouts. This is zero-credit triage, not page or class admission; exact domains and errors are in the dated screen report |
| Post-freeze v4 curated root screen | Host-local `../diagnostic-rehearsals/curated-h3-v4-20261002/curated-h3-v4-0-39.jsonl` (SHA-256 `1b05846ecfa99f22e9e422303cde4f56dce44b1723d3932a1889c1b769906c5e`) and `curated-h3-v4-40-72.jsonl` (SHA-256 `7f8cfbc34697fef22cc6398f7aa416271e0b75875294637f1b7b39baaaeb7881`) | Both create-only slices were independently reopened against the frozen v4 profile, raw source, receipt, v147 build binding, preparation image and module hashes. All 73 ordered first-screen decisions verified with eight passing control pairs: 30 clear H3, 28 ambiguous, six peer TLS handshake failures, two timeouts and seven automatic safety skips. This supplies root-screen facts only, no site admission or capture credit |
| Curated direct-browser diagnostic | Host-local `../diagnostic-rehearsals/curated-direct-20261002/idrlabs-discover-001.json` (SHA-256 `10a0e821660e575b18ff4bd6bddf004b1d8b9cecc74cdf01557d8f58ad2acdeb`) | The v147 prepare image reached direct pinned-browser discovery for `www.idrlabs.com`, then failed the 30-second passive-render quiescence check. The separate catalogue-navigation probe hit a recoverable root CDP `InvalidInterceptionId`. Neither attempt admitted a site; no source edit or new build was required to classify the failures |
| Second curated direct-browser diagnostic | Host-local `../diagnostic-rehearsals/curated-direct-20261002/weerplaza-discover-001.json` (SHA-256 `dbd9c827a12ceeaa6a863b6b25e145f9dc04a09e1e09cf5ddf0841472771975d`) | The v147 prepare image reached `www.weerplaza.nl`, then discovery rejected its root-frame identity/resource-type sequence as a noncontiguous primary redirect chain. No page graph or site admission was produced |
| First successful curated browser lead | Host-local `../diagnostic-rehearsals/curated-direct-20261002/sacnilk-discover-001.json` (SHA-256 `88ab5aecab2526c100eb535e405db64629d0ccfe383c4f890c244da0c9d45d97`) | The v147 prepare image returned a direct browser discovery summary for `www.sacnilk.com`: 42 resources, 56 requests and 14 observed origins. The initial three-origin allowlist left 14 exclusions. No complete-coverage graph or site admission was published |
| Curated 3bmeteo browser lead | Host-local `../diagnostic-rehearsals/curated-direct-20261002/3bmeteo-discover-002.json` (SHA-256 `b55a96987c77ee77326bc5d097d0ae12cbc0aab4964e8eac4da136dab966f795`) | Direct v147 discovery completed in 25 seconds and preserved the full diagnostic graph: 132 requests, 106 resources and 17 observed origins. The two-origin seed left 22 exclusions, so this is a working lead, not complete-coverage preparation or a site admission. An earlier `-001` command exited before running the Python probe and left empty diagnostic files; no result was inferred from them |
| Curated 3bmeteo expanded-origin retry | Host-local `../diagnostic-rehearsals/curated-direct-20261002/3bmeteo-discover-003.json` (SHA-256 `227d414c5face287a6a70ec604fa0a083986758350c3cc478076eecb88dbf53c`) | A second direct v147 browser pass approved the first pass's 13 expandable origins and completed with 155 requests and 136 resources. Eight GETs still used unapproved origins, including two newly observed analytics hosts, one with a timestamp in its hostname. No complete-coverage graph or site admission followed |
| Six curated direct-browser leads | Host-local `../diagnostic-rehearsals/curated-direct-20261002/six-lead-screen-001.log` (SHA-256 `18e16b4b1e69d647296d5129610d844f6f7758a05fb7647497077a7a7456891b`) and six sibling create-only JSON receipts whose exact hashes are in the [dated screen report](CURATED-H3-SCREEN-2026-10-02.md#first-browser-follow-ups) | Pinterest failed quiescence; Discord, Comfortweather and Alibaba failed separate CDP integrity checks. Poki and Toom completed first browser discovery with one and 41 unapproved-origin GETs respectively. None has a complete graph, prepared workload or site admission; Poki is the least costly convergence lead |
| Poki expanded-origin browser pass | Host-local `../diagnostic-rehearsals/curated-direct-20261002/poki-com-discover-002.json` (SHA-256 `dabb346dc628ff99447768d274d824c60878a4bd10665dde70853f64b009cd51`) | The second v147 direct pass approved four origins and completed in 19 seconds with 268 resources and 280 requests. No unapproved GET remained; one unsafe analytics POST was excluded. This is a preparation/replay lead, not a verified workload or admitted site |
| Poki complete-resource preflight failure | Host-local `../diagnostic-rehearsals/curated-direct-20261002/poki-com-prepare-001.json` (SHA-256 `e2c9d75b07b5976a0cd2ab6d461ff23a1021fa890a43a904fc86fa749002b39b`) | A bounded v147 zero-credit preparation attempt used the four approved origins from the second browser pass. It stopped in about 20 seconds because resource 253, `https://poki-auth.poki.com/sessions/whoami`, was unavailable to Neqo over HTTP/3. No stability replay or workload was produced; Poki is not admitted |
| Poki relaxed-coverage feasibility failure | Host-local `../diagnostic-rehearsals/curated-direct-20261002/poki-subset-001.json` (SHA-256 `e57b7dfb36ee9aa4f32597966b88608a2a7b1e417669e6d5cd411da25f23c82c`) | A separate zero-credit generic preparation allowed recorded HTTP/3 exclusions and ran two stability checks. The main document and 52 retained resources changed or failed; no workload was published. This does not revise the frozen v4 complete-coverage policy |
| Haberler browser-settling failure | Host-local `../diagnostic-rehearsals/curated-direct-20261002/haberler-discover-001.json` (SHA-256 `9e487db50a9be915ed8b2098c002fa3dfbd90c5461742ea78df135eaac08745d`) | Bounded v147 direct discovery for a clear-root, two-origin-hint candidate failed the 30-second passive-render quiescence check. No resource graph or site admission was produced |
| Curated complete-origin retry | Host-local `../diagnostic-rehearsals/curated-direct-20261002/sacnilk-convergence-001.failure.json` (SHA-256 `4723a5321e9b8e06d77f6ca453357720045690cbfb24a324bdcf8d84945cb202`) | The first `www.sacnilk.com` pass yielded 14 expandable origins; the second, with all 14 approved, failed passive-render quiescence and a CDP frame-detachment audit. No complete graph or site admission was produced |
| Historical fallback page recheck | Host-local `../diagnostic-rehearsals/curated-direct-20261002/zoomlife-discover-001.json` (SHA-256 `1969e08ab12b978da181fbfc05b122ebe67696d9ca427d07fe3a0ef698336839`) | The site `zoomlife.ir` had a valid two-origin diagnostic graph on 1 October, but a 2 October v147 direct recheck stopped before browser launch because its public DNS gave no usable A/AAAA address in two lookups while the control resolved. No current site admission or capture credit |
| v147 five-workload response diagnostic | Host-local `../rapid-execution-v147/artifacts/rapid-preflight-five-modes-20261002/bundle/config/chaff-response-qualification-store/sets/rapid-v147-diagnostic-five/_qualification-set.json` (SHA-256 `c0cfabf3ad36c0e41366fa159fdedd964c5b74b8dc7c919ade18ca747112425d`) and five sibling sidecars | Fresh preparation-image response qualification ran 5m37s, published all five sidecars create-only, and independently loaded with all five selected modes in the collection image. This tests the current v147 implementation but gives no rapid-class or formal capture credit |
| First five-mode capture attempt | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-five-mode-001/20261002T102428.030121Z/` (`evidence.sha256` SHA-256 `14ff841bc2c6e6971cf203e1457d21a8761ba0ade31b0c3a7b2f7401b6fb716e`) | ETF router setup passed on retry and all 25 diagnostic slots were attempted, but client DNS resolution failed in the isolated network before any response. The sealed incomplete result passed independent v147 collection-image deep verification: 0 accepted, 25 failed, 348 authoritative files. This is a diagnosed engineering failure with zero study credit; old evidence remains create-only |
| DNS-pinned one-visit capture retry | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-dns-001/20261002T104239.120989Z/` (`evidence.sha256` SHA-256 `e41444b0d061afa01cf3cca2cf4dbb7721ba802e9b3ebf76944c970704ff21e8`) | Public DNS preflight pinned all three approved origins and the capture reached Neqo. Each destination sent QUIC Initials, but the client saw no inbound UDP payload and the run ended in `Transport(IdleTimeout)`. Independent v147 collection-image deep verification reported a sealed incomplete result, 0/1 accepted, 17 authoritative files. Zero study credit; router return path is under diagnosis |
| Isolated router-path comparison | Host-local `../rapid-overlay-v147/artifacts/rapid-preflight-five-modes-20261002/router-path-001.log` (SHA-256 `0ece1aee3a567694b21fd9086bb5cfc444dba645ccbafc14ee25e7e6b89f3e9d`) and `router-path-002.log` (SHA-256 `cb15229229133fe8dd512f24e13e6540958a1d420591965ab5a2ccd6ea1d9b6b`) | In a bounded zero-credit comparison, the Docker `--internal` client bridge timed out on TCP/443 and UDP/53 with zero router forwarding/NAT packets. An otherwise matching ordinary dedicated bridge received both replies and counted two NAT packets. This isolates the blocked return path; a new sealed QUIC sample must still prove the launcher change |
| Router-fixed one-visit capture retry | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-router-001/20261002T110129.525509Z/` (`evidence.sha256` SHA-256 `6b89e89cea3f68ad580d44290e06e0599c5884c648c7ec621eedf8d27e6ecbb6`) | The dedicated bridge and public IP pins let Neqo complete all six resources over three HTTP/3 endpoints; the direct pcap has bidirectional packets. The result remains sealed incomplete, 0/1 accepted: the scheduler observed an extra `tini` task on a protected CPU and 39 runner-recorded packets, all associated with the second endpoint, were absent from the direct capture. Independent v147 collection-image deep verification passed the incomplete inventory with 17 authoritative files. No study credit; a second packet observer is being prepared |
| Independent-router-observer capture retry | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-observer-001/20261002T111626.017657Z/` (`evidence.sha256` SHA-256 `a023a46f8a9265e1ce3394077bcad85e56ce12f98bb3382be0a0282627d3810a`) and create-only router pcap at `../rapid-overlay-v147/artifacts/rapid-preflight-five-modes-20261002/router-observer-001.pcapng` (SHA-256 `5f54f6d3a15cca38b82a3c5599cd21504f277ef0b0de60304af170bfd2470f3f`) | All 484 runner packets reconciled to 486 client pcap frames; two extra incoming tail frames were permitted, and capture-clock integrity passed. The separate router observer recorded 494 frames. Only the extra `tini` PID1 affinity failed scheduler runtime evidence, so the run sealed incomplete, 0/1 accepted, and independently deep-verified with 17 authoritative files. The previous 39-packet gap did not recur; this still grants zero study credit |
| First complete rapid-launcher capture diagnostic | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-affinity-001/20261002T112411.099525Z/` (`evidence.sha256` SHA-256 `c3c7197a8600478459c26226f1b7a341b6c1d8331801d095dcaf120ad8eec4e3`) | A host-only PID1 affinity wrapper preserved the protected client CPU. The v147 collection image completed and independently deep-verified one three-origin undefended sample: complete, 1/1 accepted, nine authoritative files. This proves the repaired rapid launcher can produce an accepted trace on a historical workload; it is zero study credit and does not qualify any of the five traffic settings on the prospective sites |
| One-site five-mode capture diagnostic | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-five-mode-one-001/20261002T113645.532904Z/` (`evidence.sha256` SHA-256 `4b0d5355f9b3acf086735d38aaae10a9565f3466b0e427a4f2bb5f3dc16400a9`) | The independent v147 deep verifier reported `valid:true`, sealed `incomplete`, 3/5 accepted and 57 authoritative files. Undefended, FRONT and Tamaraw passed. BuFLO's first exact-timed `SCM_TXTIME` send returned `ENOBUFS`; CS-BuFLO completed application work but the first endpoint later hit `IdleTimeout` with pending egress. All attempts are zero-credit historical-workload diagnostics, not the ten-site rapid shakedown |
| Full-ancillary ETF capability probe | Host-local `../diagnostic-rehearsals/etf-full-ancillary-20261002T115745Z-ed614b8b/probe.json` (SHA-256 `ca6bcf142c19cfc6f7b388bb1dc3027b1e0997ce6710a04790760cd60942a96b`) | On the current WSL kernel and a fresh bridge, all nine full-ancillary and four serialized-priority timed sends were accepted and received, with zero ETF drops. This zero-credit probe shows the socket ancillary combination can work; it does not prove sustained BuFLO capture fidelity or explain the earlier `ENOBUFS` by itself |
| BuFLO-only launcher preflight failure | Host-local `../diagnostic-rehearsals/rapid-buflo-retry-20261002T120239Z-f1d2e038/launcher.log` (SHA-256 `6d7db8375d2b6b3a429268088b4b3798e80dd3def1ae70006b951166260ab6c1`) | The first single-mode retry stopped before creating a capture result because its relative parameter path resolved to the absent `/config/defense-params/buflo-live.json`. It was corrected in the next create-only campaign; this attempt has no accepted trace or campaign seal |
| BuFLO-only three-attempt capture retry | Host-local `../rapid-overlay-v147/results/rapid-curated-tranco50-v2-diagnostic-buflo-one-002/20261002T120718.601076Z/` (`evidence.sha256` SHA-256 `5f09f38cc592379efd137b11be8383665883c68371f68b863f45433adeeceb88`) | The independent v147 deep verifier accepted the sealed inventory as valid but incomplete: 0/1 accepted, three failed attempts preserved, 62 authoritative files. Attempt 1 completed 940/940 outgoing cells and reconciled all 1,527 kernel-TX items with zero ETF drops; its incoming-credit predicate failed because the recorded maximum action-to-advertisement delay was 6,386 µs against a strict `<5,000 µs` gate. Attempt 2 reached the enqueue cutoff before `sendmsg`; attempt 3 recorded an ETF `TxtimeDropDiagnostic` (`errno=125`, `Missed`). The action clock includes intended prearming before the nominal slot release, so the first predicate's interpretation needs prospective source review. No attempt is retro-credited; this historical workload gives zero rapid-study or formal credit |
| CS-BuFLO source regression tests | Host-local `../diagnostic-rehearsals/csbuflo-rust-tests-rEw3RQf6/focused-rust-tests.log` (SHA-256 `4ac5c5d02e0bbbabc7b40f252915b8d6fe13c3e603433326ed966b6194a3bc02`) and `crate-regression.log` (SHA-256 `c08417a8bb3ce99381fde40abe8684b8b47bf3c70cecf39e285ee47c3f73d744`) | Offline tests against the authoring Rust source passed three focused parser/stop cases and all 406 `neqo-csdef` crate tests. These source tests support the proposed final parser-credit bridge; they do not prove a corrected live capture, a completed client image, or formal readiness |
| CS-BuFLO direct debug failure | Host-local `../diagnostic-rehearsals/csbuflo-direct-debug-20261002-RDDmsO/command.log` (SHA-256 `8a1060e1adcf7a518d79645dbedfece41c987c03899aa219abb7639c701825a9`) | A direct debug client attempt stopped on `AdapterDeadlineLateHandoff` before it could test the final parser-credit tail. It produced no sealed host capture or rapid-study credit and does not refute or prove the proposed parser repair |
| CS-BuFLO release binary and direct client success | Local ignored `artifacts/rapid-csbuflo-regression-20261002/target/release/neqo-qcsd-client` (SHA-256 `f3999f6f3c9719c40909e71454aaaf316a57c2d6662a1d906e1cbdec3cb1e778`); host-local `../diagnostic-rehearsals/csbuflo-client-debug-build-20261002-ibMGFL/build-release.log` (SHA-256 `57bfc5204b2776669ac68a95c88440563c08807006e1aaa8e152afec3e9b8c68`) and `../diagnostic-rehearsals/csbuflo-direct-release-20261002-APK5id/run/run.json` (SHA-256 `1b3928e290ef330b548a69d237d0b9a04085aeff21eea00a7d344a0b3eaf5f9c`) | The incremental release client build completed. A zero-credit direct client run on the historical Cloudflare workload exited successfully with `completion_status=complete`, 876 incoming cells and exactly 525,600 bytes requested, advertised and consumed, with zero retired or unresolved bytes. This validates the client path only: there is no independently verified host lane or packet capture, no admitted rapid site and no formal credit |
| CS-BuFLO host qualification provenance stop | Host-local `../diagnostic-rehearsals/csbuflo-release-host-20261002/STATUS.md` (SHA-256 `a0442ffcbb6acfc2115d61b49eccb7c2939fb5b9d807185ad36d3a399b1e23a0`) | One-site response qualification and routed host capture did **not run**. The patched client came from an uncommitted Rust change but embedded the old clean Rust commit; the existing sidecar and v147 image identity bind the old binary. Adjusting a copied image receipt would hide that mismatch. A clean Rust/Lab source successor, matching binary/image receipts and new qualification are required before host proof. This status grants zero credit |
| Clean CS-BuFLO routed host successor | Host-local `../diagnostic-rehearsals/clean-rapid-runtime-20261002/runtime-overlay/results/rapid-curated-tranco50-v2-diagnostic-csbuflo-one-002/20261002T133530.735838Z/` | Independent deep verification reports complete **1/1**, 15 authoritative files. The result binds clean Lab `6260c3b1a5e0d5a14dbdc8e2fe443bf506969aac`, Rust `23b854e1a25e0af7834c7691cbfe53a84e6ae98c` and collection image `sha256:fc3608b0919ee2486d2c6ad0cf03f77551972195b6800fd6c59f193a243b8ad4`. Result seal SHA-256 `2256a2c5464a58cd135371b1803e4755e240c0b5d2dd2068dd5ea0c29fe60958`; `experiment.json` SHA-256 `4ede0224bc80299ad07c668d31a56bb26a6f33f2f9fad4d3a388ab35af0c39ea`. All three origins remain; packet capture, receive credit, router and scheduling evidence verify. Historical workload, zero study credit; final-cohort compatibility remains unproven |
| Clean BuFLO routed host successor 003 | Host-local `../diagnostic-rehearsals/clean-rapid-runtime-20261002/runtime-overlay/results/rapid-curated-tranco50-v2-diagnostic-buflo-one-003/20261002T133849.704365Z/` | Same clean runtime as the CS successor. Independent deep verification reports valid but incomplete **0/1**, 27 authoritative files. Rust stopped after about 1.42 seconds because protected selection slot 82 expired in CLOCK_TAI before dispatch. This precedes the Python release-window acceptance check. Preserved result seal SHA-256 `ace2a9f7002e1d8c2ae6566db84526aaa00476fa9d5cd2d06bf3dd58719dc6e6`; `experiment.json` SHA-256 `b86f889faac9aa06c0bad03c8417cc5d0742826a4abc2c90e9d77e90d88798fa`. Zero formal credit; a bounded unchanged-source retry is separate |
| Clean BuFLO routed host successor 004 | Host-local `../diagnostic-rehearsals/clean-rapid-runtime-20261002/runtime-overlay/results/rapid-curated-tranco50-v2-diagnostic-buflo-one-004/` | The bounded retry on unchanged source/settings passed independent deep verification **1/1**, 18 authoritative files. All 939 outgoing cells and 1,526 kernel items reconcile, with zero ETF timing errors; the nominal incoming release window stayed below 5 ms. Result seal SHA-256 `836dbb394d5b8ecf2d99edc7df6af7b836c60529e31cbc478a9694595ac4d366`; `run.json` SHA-256 `76db474881061b3fa690c8bc5a4e4f36e87e729894b5a435dc2e4b3278aaf395`. Host cleanup initially reported a router-removal error; the verifier recovered the durable lifecycle and confirmed its absence. Historical workload, zero study credit; predecessor 003 remains incomplete |
| Prospective BuFLO release-window source check | Current authoring `src/qcsd_lab/fidelity.py`, `src/qcsd_lab/orchestrator.py`, `tests/test_buflo_study.py` and `tests/test_campaign.py`; no standalone create-only host test log | The proposed gate measures credit timing against the nominal scheduled release instead of the earlier prearm action. Four direct focused tests and a 51-test related host selection passed; the previous sealed retry still deep-verifies as valid but incomplete, 0/1, under the proposed verifier. Source-level checks grant no retro-credit or live BuFLO readiness; a new single-mode capture is required |
| First v4 Tranco fallback root survey, diagnostic only | Host-local `../diagnostic-rehearsals/rapid-fallback-h3-20261002/fallback-000-009.jsonl` (SHA-256 `20da871f823f9b7bcd8cd9e3103adc8acee8c7da2f77919719d0539076e24b75`) | Ten frozen candidates at global positions 74–83 were probed between known-valid controls: zero clear H3 roots, six timeouts and four ambiguous observations (three generic local DNS resolver errors, one `known_valid=false` response). The independent v4 verifier rejects full screen credit at the first generic resolver error, which the frozen policy cannot classify as a terminal decision. These are ten raw diagnostic observations, **not ten verified first-screen decisions**, site exclusions or admissions. The frozen prospective v5 profile does not retro-credit this v4 log |
| First verified v5 Tranco fallback root screen | Host-local `../diagnostic-rehearsals/rapid-fallback-h3-v5-20261002-001/fallback-000-009.jsonl` (SHA-256 `852599148d9e473383bca8713ddb922460e2c2dadfcf1f54526a339a4581767f`) | A fresh post-freeze log binds v5 profile SHA-256 `f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60`, preparation image `sha256:b57eb71a063207341aadd894d0a72fa6a865aee3f557c8b6e098cff4fea2bed8`, survey-tool hash `bc66c804123053c8c7b662e62a53281b5cb0234944d895da0781455769a002f4` and profile-module hash `524673be1db426acb94fbff89f6e45a3da5ed7573f83409ee1ce43c0f58e1944`. Independent `verify_v5_fallback_h3_survey_logs` accepted exactly fallback indices 0–9 (global 74–83) between two `known_valid` controls: six timeouts, three exact DNS-name-not-found operational deferrals and one response-known-invalid ambiguous result. These **are ten verified v5 first-screen decisions**, but zero clear H3 roots, zero selected-page proofs, zero site admissions and zero formal traces. The old v4 log remains diagnostic only |
| Pre-v148 test-only repair rehearsal | Host-local `../diagnostic-rehearsals/v148-prebuild-20261002-1/acquisition-correctness-excluding-host-io-stall.log` (SHA-256 `4ad41cb679e310671d8644d5c0bd4bebfd02889fea3584cc981b4c69b280d206`) and interrupted full-run `acquisition-correctness.log` (SHA-256 `c6e5170cecb114385575c425b4f25b00ba76d758fbb3746558b00a4c8219ba6a`) | Corrected source tests passed 2,565 with six host-specific skips and one deliberate deselection of a disk-stalled case that passed in the v147 container. The first host run had passed 1,444 before interruption at the same host I/O stall. These zero-credit checks do not replace new in-image authority |
| v139 browser-fault rehearsal | Host-local `../diagnostic-rehearsals/v139-failrequest-discovery-20261002-2/events.jsonl` (SHA-256 `29a873ba83ab99b175df0c766fe369b3de8a9a744e33a1824818fb75c80ccfc4`) | Zero-credit navigation on `tranco-0000280` reproduced the exact browser fault under a proposed full-attempt discard path. It classified the attempt as recoverable but neither repaired nor promoted the official v139 checkpoint |
| Nominal-window Rust test diagnostic | Host-local `../diagnostic-rehearsals/rust-exact-handoff-v137-20261001/focused.log` (SHA-256 `c14d7e4e84e9fd9a49ea94fc36ddd4d17cf5d4a0a0083846db3a6839e82e64dd`) and `neqo-bin-repeat-r1.log` (SHA-256 `ea3b5716f9ead85f1c8e4102cc69cc4222cad1e485cf09a1b762ba4df0cf7bad`) | The formerly failing test passed once, then three full 285/285 `neqo-bin` batches passed in the pinned Rust/NSS diagnostic toolchain against clean read-only source. Zero-credit engineering verification; a fresh no-cache build is still required |
| v134 live root CDP reproduction | Host-local `../diagnostic-rehearsals/v134-root-late-network-20261001-1/events.jsonl` (SHA-256 `1f9b6e697d4361b21f2348ec1b5b4e12311e339d368489e37ec5cdaea5d6d789`) | Zero-credit two-worker navigation-only diagnostic in the v134 prepare image reproduced the pinned exception on two root Font requests. Sanitized events show `Fetch.requestPaused` before matching `Network.requestWillBeSent`; this diagnostic is not an acquisition terminal or source-bound authority |
| Proposed retry live check | Host-local `../diagnostic-rehearsals/v134-proposed-root-retry-20261001-1/run/events.jsonl` (SHA-256 `9c74f9932b7b8c42fd1a3f2460829089fa915edba7620e5577c34d2d6d5231ee`) | Zero-credit two-worker navigation in the v134 prepare image reached a distinct root Font Fetch-only `InvalidInterceptionId`: the matching Network start or terminal never appeared. The strict late-Network guard failed closed. One other candidate navigated. No formal checkpoint or scientific numerator changed |
| Revised retry live checks | Host-local `../diagnostic-rehearsals/v134-proposed-unpaired-retry-20261001-1/run/events.jsonl` (SHA-256 `5142bd8e92b4da462f282acfb8251839430a41e7598b50d4aae42c6958b10771`) and `../diagnostic-rehearsals/v134-proposed-single-nav-20261001-1/run/events.jsonl` (SHA-256 `be1305b17665b7e259c14bb430f1f4cb07766fb8b3949808dcc59a84c3d2c54c`) | In the revised two-worker check, one candidate navigated and the other hit an exact late-Network Font fault, which was discarded after cleanup and classified recoverable; the diagnostic exits incomplete because it does not perform coordinator retries. A fresh single-worker check of that candidate navigated in 33 seconds. These are zero-credit checks with mounted proposed source; no formal root changed |
| Prebuild acquisition rehearsals | `../diagnostic-rehearsals/` in the local sibling workspace | Create-only, zero-credit host/container/live diagnostics, including the control-bracketed 600-root survey, failed attempts, one complete two-origin prepared catalogue graph, and local capture checks. Not a portable checkout dependency, formal acquisition root, or authority receipt; the [rehearsal report](ACQUISITION-REHEARSAL.md) records exact counts and limits |
| Current-client Zoomlife diagnostic | `../diagnostic-rehearsals/zoomlife-schema12-directional-20261001-1/` in the local sibling workspace | Zero-credit exact-page H3 screen, 63-resource two-origin deep-validated schema-2 preparation, five-request schema-4 and 40-request schema-5 Rust response receipts. The receipt-consumer check bypassed only the diagnostic binary's `migration_commit="unknown"` provenance format; it is not formal qualification or a portable checkout dependency |
| Current-client capture diagnostics | `../diagnostic-rehearsals/zoomlife-new-client-capture-20261001-1/` in the local sibling workspace | Zero-credit public Zoomlife sealed incomplete capture after its main document changed; local two-origin `local-seal-2` accepted and deep-verified 2/2 undefended samples with source cleanliness recorded as unknown. FRONT/Tamaraw and Walkie-Talkie local wire tests passed with the diagnostic provenance parser substitution. `local-vertical-1` preserved a second-origin prefix failure. After the scoped schema-4 fix, `local-vertical-2` passed three response and three prefix qualification waves, then accepted and deep-verified a two-origin FRONT sample. `local-wt-1` consumed its exact full prefix sidecar and sealed 1/1 accepted. After the shared Rust HTTPS-origin fix, the rebuilt client repeated this as `local-vertical-3` and directly linked `local-wt-2`, both 1/1 accepted. The latest packet test invocation passed FRONT/Tamaraw and Walkie-Talkie; its broader capture test deep-verified and then failed a formal clean-source assertion against unknown diagnostic provenance. The unpatched verifier rejects unknown/dirty diagnostic provenance as expected. `local-seal-1` inherited stale v130 metadata and has a separate invalid-for-authority note; preserve it but never cite it as source-bound evidence |
| Prospective HTTP/3 screen | New source-bound acquisition checkpoint, once executed | Schema-12 pre-baseline controls and exact selected-page URL outcomes belong in the hash-bound navigation-attempt ledger; historical schema-11 receipts remain verify-only and no v129 classification is replaced |
| Original ledgers, papers and unique local research files | Original relative paths recorded in migration manifest | Thesis sources and lossless documentation provenance |
| Source backups and operational continuation | Git bundles and uncommitted migration handoff | Local/legacy revisions, published commit identities, transfer checksums and machine-specific recovery context |

### Rapid selection revision 2, 3 October 2026

The create-only [selection receipt](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v2.json)
was published at `2026-10-02T15:19:12.576895Z`, SHA-256
`32cd9eb8440c86f204919bde64a5f27cdcf1efcf28e7becf127d8e3798266457`.
It preserves the complete workload graphs and **50 × 5 × 64 = 16,000** target.
The automatic public URL/domain screen has explicit scope; it is neither a
human review nor a content classifier. Only narrowly typed failures with their
raw evidence can produce the new zero-credit page screening decisions.

Host-local context
`../diagnostic-rehearsals/rapid-v5-site-acquisition-20261003-003/`
has independently reopened provenance SHA-256
`a8bc132c7464bb2ebc5ff6d512593b9caf77d1d2c365a33b692cdfac2d8661e2`
and launch-manifest SHA-256
`ac1548ce607fe3135be18af9fe2c37136315c9ef3f4787c068ba23f1a03eeaf4`.
Its first two terminals are search-fast's controlled root deferral
(`a2c77fe0ecf72d9e82ad84cfc6ff2d0982e9b45bd8b7e86c561eeb24d7e3b648`)
and a fresh Weerplaza WebSocket policy failure
(`508a2dda8264e7681cd4c2518ee853d0d678f980a62b3d6c52fa7437739df1ae`).
Both have zero scientific credit.

Albumaty's automatic screen at `2026-10-02T15:28:20.116708Z` has SHA-256
`e89445c77ee76ac6e4da890ced59e68f510c9c1198cd5799672cba4d9321c8f7`.
It binds the independently reopened exact-page navigation receipt
`cd686decfeb4189c0710256ed99336b6d4267a8c0c7a9aca5bc1f980bd2cf4dc`
and controlled H3 receipt
`f4b9b863b0bf4386faf6fabd8022deacc20d6d922b240435f8b8b9eb8dfc4a2d`.
Complete preparation attempt 000002 and unchanged-source retry 000003 both
failed because the Neqo HTTP/3 resource probe exited 1 after endpoint 2 closed
with `Transport(Peer(296))`. Their `operational-error.json` and
`origin-convergence.json` files are preserved; the latter records the complete
31-resource, six-origin discovery. The generic failure path discarded the
inner temporary probe files, so it cannot support a retrospectively typed
screening decision or exact endpoint attribution. A new source-bound producer
must retain those files during a fresh attempt. No site or trace was admitted.

Fresh context
`../diagnostic-rehearsals/rapid-v5-site-acquisition-20261003-004/`
uses preparation module SHA-256
`a70b5cd710dbfdeb1b42647bf3bf283113f7d6a2ca926ba7303c3c6ab2251f38`
and acquisition-error module SHA-256
`a271797308e8fc55abcf861b79e6869564c84083b4b0f8b4faab8ee6bd8b8e02`.
Provenance SHA-256 is
`2e263996644937c7ab252680311bf55afab916a4c425c4cdfc6ec40a6dc4cb17`.
Its fresh Albumaty failure receipt has SHA-256
`7b64c5233cfc5f0ac64e12ed010944b98a88b680362a87659dada27f6928cc3c`;
the independently reopened explicit terminal has SHA-256
`4c5c880f46c7d5f51b5f479c93486f81dbb8fb6d77125902ae8732c606142034`.
The actual retained HEAD run identifies endpoint 2 as
`https://use.fontawesome.com`, resource IDs 5, 23 and 25. The schema-2 proof
retains the complete probe input, child exit 1, run, schedule, packet/event
evidence and exact peer-296 failure. There is no fabricated successful probe
manifest or `known_valid` result. It grants a zero-credit screening deferral,
preserving context 003's two generic failures unchanged. Context 004 has four
verified screening decisions and no admitted sites; Alibaba's catalogue
navigation subsequently passed. Alibaba also passed its controlled exact-page
H3 check and automatic URL/domain screen. Full preparation stopped after a
30-second passive-render limit; cleanup reported `CdpTargetIntegrityError`
(`root Page frame detachment identity is invalid`). Its retained operational
receipt at `acquisition/attempts/curated-30f778352dfbe9e2e48c/attempt-000004/operational-error.json`
has SHA-256 `f455937829c5a33d795892ee69124900d7c45d10c777b6a5df770b687ddb825d`.
The traceback in `operation-plans/plan-000006/prepare-stderr.log` retains both
errors. No raw frame-detachment event parameters were retained, so the exact
event sequence is not established. This remains an unsealed operational failure
under revision 2, with no site or trace credit.

### Rapid selection revision 3, 3 October 2026

The create-only [revision 3 receipt](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v3.json)
was published at `2026-10-02T17:00:14.866744Z`, SHA-256
`e175fa86345946999af391ec3a98115abd2b84c4cfffdce075dab10b09e3ad3e`.
It binds the actual revision 2 parent above and preserves the **16,000** target,
five traffic settings and complete admitted resource graphs. It permits a
newly observed direct `CdpTargetIntegrityError` from a frozen event handler to
advance screening as an operational collector deferral, never as an eligible
site or a finding that an entire domain is unusable. Raw exception chains,
tracebacks, source/client bytes and the closed attempt inventory must reopen.
Preparation observations also bind the exact-page H3 pass and automatic
screen. Missing CDP event parameters are explicitly unavailable, not inferred.
Generic setup, infrastructure and wrapped generic errors remain blockers.

The observer source SHA-256 is
`2fa4b8082ec9ec095e76804bf0234929eaa482025d7a8aadd6c4e857e258745b`;
all 16 focused observer cases passed. Amendment source SHA-256 is
`60151f1f7dca6cde49640840880b695915687a7319e67fa883b20c289f9d688c`;
111 compatibility and policy cases passed, including byte-identical historical
v1/v2 receipts. Admission source SHA-256 is
`98cca9044be68a61d5e9e10837a164e53dce0e1685a9dc60e69bdb7f729610c6`;
CLI SHA-256 is
`3c7dadfd2bb5c6d978c469e41212f23f482d62e7896d8f068e40edfa1879f0f2`.
Focused admission/CLI and capture-planner/adapter integration checks passed.
These are engineering checks, not fresh live collector-failure evidence or
capture credit. No old context 004 attempt is promoted by this policy.

Revision 3 also permits a controlled completed `response-known-invalid`
homepage observation to proceed to browser and exact-page checks, retaining
its actual ambiguous outcome. DNS ambiguity, timeouts, peer closes and missing
controls cannot enter this branch. Historical v1/v2 rules remain unchanged.

Fresh host-local context
`../diagnostic-rehearsals/rapid-v5-site-acquisition-20261003-005/`
has provenance SHA-256
`03f28e58613c18c086f24473933473642e9c757f992df41d9a04431f062f5164`
and launch-manifest SHA-256
`29999ddd146f181ed433d333f3f44bd53b07f04912bf7350a135dde30ffeb5a9`.
Its controlled root deferral and fresh Weerplaza observation were independently
sealed, giving a terminal prefix of two with zero admitted sites or formal
traces. The real navigation invocation completed in 26 seconds at
`2026-10-02T17:07:40.335752Z`; its observation SHA-256 is
`053a59559784d2e00a060c7e59a0f5de6bf4148b1e4707855c4376a9dbf9b4a1`.
Albumaty's separately executed fresh automatic screen has SHA-256
`2fd1b9c2bfdccdc6bb9003ba40c6dfa3642d94b2483243a1579efddd803f679b`.
Its new full preparation completed in 73 seconds at
`2026-10-02T17:13:43.445309Z`, retaining the actual FontAwesome peer-close
failure (resources 5, 23 and 25). Typed failure receipt SHA-256 is
`821e2a9974e960f559205d0ffa859517395ca082f028dd4fa8cd8eac0527c747`.
That failure was independently reopened and sealed, then the fourth candidate's
controlled root deferral was sealed. Context 005's prefix is now four, with
zero admitted sites or traces. Alibaba's fresh automatic screen has SHA-256
`9f6a0752fcac5ea214c4ae6210764f47edef816c1bf982cf7eb08697ec4d2977`;
its new full preparation completed in 65 seconds at
`2026-10-02T17:19:49.103453Z`, with the fresh collector observation already
retained and verified by the producer. Observation SHA-256 is
`1b6461ec334d1a852aad3513cb93e46c86d78a855fefb0030b668a17e62eb0b5`;
outer wrapper SHA-256 is
`a66a32e946ae72126a6d7711c71cff482aae82521a37f087404d0930295bf3f2`.
The actual traceback ends at `cdp_targets.py:5070`,
`_handle_root_page_lifecycle`, with exact `CdpTargetIntegrityError` and a
retained primary `PassiveRenderPolicyError`. The source/client inventory has
all 13 bindings, including the final observer. This is the fresh revision 3
path, not a promotion of context 004's error. A separate audit reopened all
18 closed files (9,009,835 bytes), the source/client bindings, retained
exception context and all three page-support receipts. The explicit collector
terminal then sealed successfully with empty stderr. Context 005 now has five
verified screening decisions. Pinterest navigation subsequently stopped with
an unsealed operational error. Site and trace
credit remain zero.

### Pinterest navigation operational failure, 3 October 2026

Context 005, candidate order 6 (`ca.pinterest.com`), actually ran plan
`operation-plans/plan-000008/navigate.json` inside the bound prepare image.
The Docker action started at `2026-10-02T17:39:50.760859+00:00` and ended at
`17:40:04.099910+00:00`, exit 2. Its empty stdout and retained stderr show
`TerminalProbePolicyError: page-safety-rejected:captcha-or-challenge-widget`.
The host-local context is
`../diagnostic-rehearsals/rapid-v5-site-acquisition-20261003-005/`.
Execution-record SHA-256 is
`a9b18378b70c1a2328bbd7c1e8ac25aa54ac290e98c9e9bd067404be8f15a488`;
the attempt's `operational-error.json` SHA-256 is
`790c5e73c90dae9a33c41012ebb1a22ccab9ae1305476c06a3a0f2687cad2b24`.

The attempt retains only intent and that operational error. No rendered page,
selector matches or challenge visibility evidence survived. The existing
detector includes mere script presence, so no active CAPTCHA claim is made.
Revision 3 has no seal route for this error. It remains unsealed, retryable
operational history with **zero site and trace credit**, and context 005 is
stopped. A new observer must collect a fresh attempt under prospective rules;
this old message cannot gain their authority.

### Rapid selection revision 4, 3 October 2026

The create-only [revision 4 receipt](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v4.json)
was published at `2026-10-02T18:13:34.038260Z`, raw/canonical SHA-256
`0808c27b60b229de938bd8a3ae26aca615455c3c4978130b4792041787420a28`.
It binds the actual revision 3 parent and keeps **50 × 5 × 64 = 16,000**,
complete admitted graphs and the separate 50-trace shakedown unchanged.
One actual unsuccessful navigation, selected-page HTTP/3 probe or complete
preparation call can now finish screening with **zero site and trace credit**.
The proof retains the actual exception and a closed inventory of available
attempt files, under independently checked source and runtime bindings.
It records an unsuccessful operation, not a visible challenge, particular
page-content defect or whole-domain verdict. A negative selected-page probe
also needs passing before/after controls. Input, runtime, source, configuration,
dependencies, permission and post-call verification failures remain blocking.

Failed preparation now retains actual raw logs, probe inputs, schedules,
manifests and available packet data before temporary cleanup. The diagnostic
copy does not classify the failure or grant authority by itself. Its source
SHA-256 is `ca490f2a160f186baeff8e153906f83ff5d64577823475f0a06c7e78495c8fd4`;
11 focused retention and compatibility cases passed. The final observer source
SHA-256 is `84ef4c6f1bfae747674208b6ac6d0ab4d7e85d95222a6fb401865b759a364aba`;
21 focused cases passed in 79 seconds. No image or client rebuild was needed.

The integrated admission/CLI checks passed nine distinct critical v4 cases,
including real explicit sealing, blocking validation causes and retained
typed primary errors. Sixteen distinct amendment gates passed, including
historical v1/v2/v3 receipt rederivation and preservation of the full target.
The frozen admission SHA-256 is
`96b7f4f71af3ad1d6753be6e742ee222d718521be0b26d04e2de3bebd309a4c6`;
CLI SHA-256 is
`df74636216dfe8367dfa25d3c29fe871cac85b60fbc464086e8db27d3b0157f0`;
amendment source SHA-256 is
`e1320b84048350524fbbe2f14212a24e87ec6734934a76253b0baaeecad291ab`.
These focused engineering checks add no live site or capture credit.

Fresh host-local context
`../diagnostic-rehearsals/rapid-v5-site-acquisition-20261003-006/`
has provenance SHA-256
`a2d728946642e8706b701f08d4ae8a08d550a3e3bfbbca42b7014b1cce1516af`
and launch-manifest SHA-256
`a9629ef6c000132a431de2260504308b0042263d4f26dd145db0a1e1e05dd986`.
Initialization completed at `2026-10-02T18:15:00.045215Z`, exit 0 with empty
stderr; `init-execution.json` SHA-256 is
`29f12053911a42aa353d806805cf3f521b6feb3f700ea04c4d1a7f99869814e6`.
Its eight frozen groups include 18 bindings for the unsuccessful-attempt
observer, including the actual client. Positive root, navigation and exact-page
observations may reopen only under unchanged groups. Fresh failure observations
must postdate publication; context 005's Pinterest error remains unsealed.

The first bounded runner completed **20 operations**, exit 0 at its maximum
action count. Its 19 additional planning records are saved in
`private-runner-executions/20261002T181623.143397Z/`; actual action outputs,
stderr and execution records are in `operation-plans/plan-000001/` through
`plan-000020/`. Twenty actions are not twenty completed candidates. Independent
status reopening at **2026-10-02T18:25:41.002979Z** confirmed **eight sealed
zero-credit decisions and zero admitted sites**. Candidate 9,
`www.futura-sciences.com`, had passed navigation and still needed its exact-page
HTTP/3 check. This timestamp does not claim later activity. Study shakedown and
formal counts remain **0/50** and **0/16,000**.

The fresh Weerplaza observation ran from `2026-10-02T18:16:31.668002Z` to
`18:16:51.396892Z`. Independent native reopening passed for all 18 source/client
bindings and 22 retained files (9,279,748 bytes), including the actual
`NonReplayableEgressPolicyError`. No DOM reason or failing document is inferred.
The files are under
`acquisition/attempts/curated-d4293e19645b22a65d58/attempt-000001/`:
`attempt-observation.json` SHA-256
`451f1aa2b14769c2c0a3cd16ef520835c23361a085de0aa4b6d9f6a898922c85`;
`attempt-failure.json` SHA-256
`ebb22eaa04a62ac82dc0716d95004525970c60cbc45ccd4d94190beba276970a`.
The independently reopened explicit terminal at
`attempt-000002/terminal.json`, completed at `2026-10-02T18:16:57.668393Z`,
has SHA-256 `2aa438a6004911946f7ebf617cb44696860349fc807154d7cc84742306b40b2a`.
This is a fresh zero-credit decision; all earlier contexts and failures retain
their original rules and bytes. No separate audit-report file was created.

Additional independent reopening confirmed these fresh revision-4 failures:

- **Alibaba preparation**, `2026-10-02T18:20:23.184438Z`–`18:20:31.878195Z`:
  actual `CdpTargetIntegrityError` during origin convergence, with 18 source/client
  bindings and 23 closed files. The explicit terminal SHA-256 is
  `ff5e967163b58923109b84e13c529aaf297d6a5ce261c5227dd268edb360bf49`.
  This attempt failed before full-graph preparation; no site was made ineligible.
- **Pinterest navigation**, `2026-10-02T18:20:58.017935Z`–`18:21:06.730945Z`:
  actual `TerminalProbePolicyError` with the challenge-widget detector message,
  18 source/client bindings and 22 closed files. The explicit terminal SHA-256
  is `9b23cd7f0adfccf67449f2aa7ca4fb87327faa8787a3d192e50ab72bbabff973`.
  The saved error supplies no inferred DOM evidence or visible-challenge verdict.
- **Futura preparation**, `2026-10-02T18:26:58.191705Z`–`18:27:34.404881Z`:
  actual `PassiveRenderPolicyError`, reporting that passive render did not quiesce
  within 30,000 ms after load. Its navigation, controlled exact-page H3 and new
  automatic screen had passed. All 18 source/client bindings and 23 closed files
  reopened. Wrapper SHA-256 is
  `b10949e1b9c4bd64792d525d41aad251dfed0b1f0b9748d2f9239770f99358b3`;
  explicit terminal SHA-256 is
  `d8a4b1ad2192ef87fa5f24680986c9cb76d838530470f5852b9b277948be72cc`.

Independent current-status reopening at **2026-10-02T18:29:53.888910Z** confirmed
**nine sealed zero-credit decisions and zero admitted sites**, with candidate
10, `poki.com`, next. The bounded second batch was continuing. These dated
counts exclude later activity; study shakedown and formal credit remain zero.

#### Later bounded operations and alternative-page routing

Two separate 20-action batches returned exit 0 at their action limits:
**40 actual operations accounted for 16 candidates, with zero admitted sites**.
The 14-file source update is committed as
`905776a8876894e9db690b3a775dfe2006635c2b` and published to Lab `main` and
`desktop`. Immutable execution source, client, image and earlier receipt
identities remain unchanged.

The private `stage_next_candidate_v2.py` helper and
`run_private_operations_v2.py` controller were frozen separately in context 006,
with respective SHA-256 values
`24485db7a04daf374c4fb80f54427b1b6326569f08fb14aed776d81ebde69ffd` and
`6546c949bdfbc0fc26248df7923cbfaa29bdd91963789e4650afe4f3835d2e51`.
Eleven routing checks passed in 0.38 seconds. This operational route tries each
existing deterministic ordinal 0–4 at most once, binds the automatic screen to
the latest passing exact-page proof, and can try another page after a prepared
graph lacks a cross-origin resource. It does not reopen a sealed candidate or
change scientific acceptance, study rules, producer source, image or client.

The first v2 plan, `operation-plans/plan-000041/plan.json`, has SHA-256
`bd13508e2e9d4676465447ac37b47e4af999646179290b530e9f0793ffa919c9`.
Its staging invocation ran at `2026-10-02T18:43:02.830772Z`–`18:43:08.220864Z`,
exit 0; `next-stage-v2-001-execution.json` SHA-256 is
`13ef5e364d860a6acd0cfc278b0ddf09462ffbb0df25474d2551b0760d2e75b0`.
The next bounded **40-action** batch was running. Independent native status
reopening at **2026-10-02T18:50:47.549609Z** confirmed **21 sealed zero-credit
decisions, zero admitted sites and candidate 22 next**. These dated counts
exclude later activity. There is still no first admitted study graph, completed
study shakedown or formal capture credit.

The first new prepared workload must still exercise its response qualification,
cross-image receipt loading and a bounded collection canary. The historical
workload's passing bridge proves runtime placement, not success for that new
graph. No new first-site qualification or canary result is claimed here.

### Short Bing collector diagnostic, 3 October 2026

The separate zero-credit diagnostic at host-local
`../diagnostic-rehearsals/rapid-v5-bing-passive-render-20261003-001/`
ran the exact frozen context-006 `ExistingAcquisitionBackend.discover` once,
with only `https://www.bing.com` approved. Docker exited 0 with empty stderr at
`2026-10-02T19:19:25.336620Z`; the backend call itself completed successfully
at `19:19:22.863261Z`. The retained inventory independently reopened **22 files,
9,533,356 bytes and all 18 source/client bindings**, with the clean runtime
unchanged. The frozen render and discovery-event validators passed.

All 78 Network request occurrences had terminal events: 72 failed and six
finished. The 72 blocked Fetch requests comprised 70 unapproved-origin GETs
and two POSTs. At the render cutoff there were zero active requests, the router
was ready and no worker, egress or internal-document setup was pending. The
required quiet window lasted 3,001 ms; the cutoff was 13,001 ms after load.
This disproves an inevitable blocked-request leak in this one frozen path.
It does not diagnose the earlier timeout, whose failed cutoff snapshot was
not retained.

This was only the first discovery pass: four primary-origin resources and
`r.bing.com` identified for later origin expansion. It did not perform full
preparation, resource HTTP/3 checks, stable replays, site admission or capture.
The earlier sealed Bing failure is unchanged; **no scientific counter advances**.
`output/discovery-result.json` SHA-256 is
`a90f0ecd881ea12ed257d9e50fdb5533bd3b99cce935552948ad665c1910ac88`;
`output/evidence-index.json` SHA-256 is
`cdd799a9181d1a2ad8d4c9e8485b3800a1afb62ec6e5689a5048cc789d5f1ea1`;
`execution.json` SHA-256 is
`f8f338457b5a6219a062a53bcc214d8af13384e92d52abd3b2bf76858bb3f593`.

### Clean fallback first screen, 3 October 2026

The fresh clean-image survey at host-local
`../diagnostic-rehearsals/rapid-v5-fallback-h3-clean-20261003-002/`
completed fallback indices 0–39 (global candidate orders 74–113) in about four
minutes ten seconds, with eight passing controls. The independently reopened
40 decisions comprise one known-valid homepage (`bandcamp.com`), 15 ambiguous
observations, 19 timeouts, four peer TLS failures and one automatic safety skip.
The ambiguous observations comprise seven completed responses with
`known_valid=false` and eight exact DNS name misses. A completed ambiguous
response can proceed to browser navigation and the separate exact-page H3
check; it is not a confirmed eligible page or an automatic site rejection.
DNS misses remain visibly operational deferrals.

Raw log SHA-256 is
`06cc2f05d568c518ab8706bb08890e8df2e14400d4b81553f36bf8c759fa30eb`;
the independent verification record SHA-256 is
`771e99e392c69298daf531b583394d065a517491f694d00286276dd526d0dbc2`.
The verifier uses context 004's independently frozen fallback module and clean
runtime bindings. This supplies root observations only, with **zero admitted
sites and zero trace credit**. The preceding invocation in sibling directory
001 failed CLI argument parsing before any probe; it remains preserved without
screening authority.

### Installed rapid capture runtime check, 3 October 2026

The actual network-disabled collection-image invocation at host-local
`../diagnostic-rehearsals/rapid-v5-capture-runtime-20261003-001/`
exited 0 with empty stderr. Its output SHA-256 is
`f7b8f22da2880e444bc1ce312ad26ebb56ecf3a5947ca1c088da3c4aafec6355`;
the retained 101-file external module snapshot has SHA-256
`fda784b2e6a425bf534ad281484a5088ecac342736e84e85422b8fe8ef52c6d1`.
The frozen adapter helper is
`0e01439b4b505f8bd4a327005c6221e9b07ff09b3f1579f8aa2aef6194b312e5`.
It independently checks the installed source and client in collection image
`sha256:fc3608b0919ee2486d2c6ad0cf03f77551972195b6800fd6c59f193a243b8ad4`,
the full clean Lab `6260c3b1a5e0d5a14dbdc8e2fe443bf506969aac` runtime,
Rust `23b854e1a25e0af7834c7691cbfe53a84e6ae98c`, client SHA-256
`a21eb5fa8654e90c9ed18ecfa4280f5fdb311c592a6c89d5b963c3cd03a17380`,
base launcher SHA-256
`1ba2dcc16fe57d6ae800c75074cbf29c915ea05de7e080b6c9b2098bb26f57cb`
and separately bound host launcher SHA-256
`7216d6a689d858962d982b5bd01cfc9652f1cbb20d7c5b6fbb4a664d4d27751a`.
The v5 profile and three fixed traffic files are checked at their actual
execution paths. This is an installed-runtime check only: it supplies no
cohort, bound lane launch, shakedown trace or formal credit. Later adapter
changes require their own frozen snapshot; this proof is not a blanket pass
for unfinished recovery code.

The separate final-adapter invocation at host-local
`../diagnostic-rehearsals/rapid-v5-capture-runtime-20261003-002/` exited 0 with
empty stderr between `2026-10-02T16:42:01.998284Z` and
`2026-10-02T16:42:07.661391Z`. It uses the published portable Lab source
`1747fc16b427ebfcc492c159ddc6dfaedb03b5a8`, with final adapter SHA-256
`ac730c551b6783fb21c556017e8b11212713566d1b86ee0a145a4adf25c03fcd`
and CLI SHA-256
`48ce673eb61ef189bcbd696ef08a765cd53de01d759ae9bd91f9f79a70bc139e`.
Its 101-file module snapshot SHA-256 is
`033314652aba4bc5cb6e480b3e9c06d6ba93996fc4a4ba2339547dbcd02ba96d`;
command SHA-256 is
`2d4cdc6e526c0a2be1e0bbba1342bc19f970722e38e2d6eb4119a6d13b7ca731`.
Runtime output matches the earlier output SHA-256 above because these runtime
inputs are unchanged. This advances the final adapter's installed-runtime
check only; real bound launches, Docker retirement and formal credit remain
outstanding.

### Clean recorder tail fix, 3 October 2026

The fresh three-mode result at host-local
`../diagnostic-rehearsals/clean-rapid-runtime-20261002/runtime-overlay/results/rapid-curated-tranco50-v2-diagnostic-three-mode-one-001/20261002T141953.703830Z/`
deep-verifies as valid but incomplete, **2/3 accepted**, with 31 authoritative
files. FRONT and Tamaraw passed. Baseline failed strict packet reconciliation:
417 capture packets match the first 417 runner rows, but all 45 rows in the
last burst are missing. Capture stopped about 156 ms after that burst and its
campaign used zero settle time. Buffer retirement is the leading explanation,
not a proven kernel diagnosis.

A separate prospective baseline campaign uses two seconds of settle time:
`../diagnostic-rehearsals/clean-rapid-runtime-20261002/runtime-overlay/results/rapid-curated-tranco50-v2-diagnostic-baseline-settle-two-001/20261002T143630.770731Z/`.
Independent deep verification reports **complete, 1/1**, nine authoritative
files. Result seal SHA-256:
`4e1478185931987cb38da663fa47790eeb433c3a4065f3d46e3bc1d23146daa3`;
`experiment.json` SHA-256:
`4e507a101de3509f2a0e9074ca1161618a7575b99e2fd3bdc59974b7f908f05b`.
The verifier log `baseline-settle-two-verify.log` has SHA-256
`ce9984e025f71f979a289bfaa010e90821a381e8077a7c509171afd41bec3019`.
It uses the same clean collection image and three-origin historical workload
as the preceding clean mode diagnostics. The failed predecessor remains
incomplete; both campaigns have **zero formal-study credit**. Prospective v5
lane rendering now includes the two-second pause; historical v4 rendering is
unchanged.

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
The historical [rapid v2 profile](../config/curated-sources/crux73-tranco600-rapid-v2.profile.json)
(file SHA-256 `231cc8aebda618b943d8bba295ba70e29d15f2fa92268301bba2c0c9ecbf0b5e`)
binds those exact raw bytes and the frozen 600-domain Tranco catalogue in a
reproducible candidate order. It records study targets, not admitted sites or
formal capture authority. The historical [rapid v3 profile](../config/curated-sources/crux73-tranco600-rapid-v3.profile.json)
(file SHA-256 `cf82d02eed73ba853b15df3ba3df57201faf67023b39bd03110b70539d00de19`)
preserves both source files and candidate order while adding auditable bounded
screen deferrals and human site-safety reviews. The historical [rapid v4 profile](../config/curated-sources/crux73-tranco600-rapid-v4.profile.json)
(file SHA-256 `ac40a338bf72c9062b4ece0d1f16de6476763c522295f668e2f5fe931f8c6a92`)
requires the first controlled root screen and a recorded site-safety decision
before deep browser admission. The current prospective [rapid v5 profile](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json)
(file SHA-256 `f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60`)
keeps the same ordered 73 plus 600 candidate sources and **50 × 5 × 64 =
16,000** formal target. It records a first controlled root result, permits an
exact DNS name-not-found result as operational deferral, and requires a
separate controlled HTTP/3 pass on the exact selected page, human safety
approval, complete live graph, stable replay and cross-origin resource before
admission. A root result may be ambiguous; the selected page must still pass.
The old profiles remain verify-only. No profile alone admits a site or
authorizes capture; v5 live yield remains **0/50**.

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
