# Frozen project-ledger snapshot and continuation through 28 August 2026

> **Frozen historical appendix.** Every use of “current”, “active”, “next” or
> similar present-tense language in the source body describes its historical
> checkpoint, not the repository's present state. Use [PROJECT.md](../../PROJECT.md)
> and [CLASS-STUDY.md](../CLASS-STUDY.md) for the maintained contracts.

Source: `PROJECT-HISTORY.md`; original SHA-256 `c5f443abb1834a4b3ce12b01378fd80b9b74f1d9221a035fe5ae1b79899c8b45`; 66,625 bytes; 1,029 lines. The byte-identical
source is retained only in the external migration bundle. This tracked copy adds
stable source-line anchors, retargets links to tracked repository files, renders
ignored evidence locations as inline historical paths, and replaces any
machine-specific home or code-graph identity. No narrative, metric, receipt hash,
command, or status claim is intentionally abridged. See the
[source map](../HISTORY-SOURCE-MAP.md) for exact coverage.

---

<a id="source-project-history-md-l1"></a>
# QCSD project ledger history

> **Frozen historical snapshot.** The original ledger below records project
> state through 2026-08-18. Its contemporaneous words such as “active”,
> “current”, “next”, and “pending” are historical and must not be read as the
> present project status. The original 55,181-byte body had SHA-256
> `168d191c288af5db4e76832c669fed96c27f5c41f8c8f8537751f05fc3941e5f`.
> Establish current status from the Git checkout and immutable executed
> receipts; this local archive is not an operational authority.

The original body is preserved unchanged below this banner. A dated
continuation after it records later milestones without rewriting the snapshot.

---

<a id="source-project-history-md-l16"></a>
# QCSD thesis project ledger

Last updated: 2026-08-18

This is the authoritative ledger for the local QCSD thesis workspace. The
research-readiness goal is complete: the full-v2 qualification, sealed
120-sample fitting result, verified schema-6 bundle, and independent 14-sample
post-fit smoke remain intact. The active advisor POC is a separately prepared
five-class closed-world study. Recovery acquisition source Q3 is committed at
`06cacddc21ab0ded9422d445723f60f37c530363` and pins Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`. The replacement exact-five
qualification completed atomically from Q3/F3 and publication P3
`507cb04c38babcdc0050ddb064007a962efee0a2` commits those exact sidecars.
Immutable final P3/F3 images passed the provenance, implementation, runtime,
layer, and exact-21 campaign-plan audits. Their first required strict clock gate
returned `NO_GO`, and a subsequent passive watch confirmed persistent host-clock
slewing. A later full Windows restart restored healthy quantitative clock
behavior; a diagnostic 969-sample gate passed every original numeric bound but
also exposed transient WSL-only `STA_UNSYNC` reports between clean pre/post
states. The interpretation of that status was declared prospectively below, but
the ensuing official gate returned `NO_GO` on its added rolling-rate checks and
ended with stale Windows time data; no P3/F3 rehearsal, interface handoff, or
formal capture has started. The previous
Q2/P2/F2 cohort and its valid but incomplete 29/30 rehearsal remain immutable
diagnostics. The next gates are a fresh strict clock test under the declared
status interpretation, a new strictly excluded 30/30 rehearsal, and a
verified interface handoff before the 2,500-capture formal corpus restarts from
baseline-01. The
older six-workload 42-sample rehearsal and 126-sample engineering campaign
remain explicitly on hold.

<a id="source-project-history-md-l47"></a>
## Workspace

| Path | Role |
|---|---|
| [`neqo-qcsd-lab/`](../..) | Docker-only experiment orchestrator, workload preparation, campaigns, capture, verification, fitting, and analysis. |
| [`neqo-qcsd-lab/classifier-pilot`](../../classifier-pilot) | Offline, create-only export and verification of sealed capture results as governed classifier handoffs. |
| [`neqo-qcsd-lab/neqo-qcsd/`](../../neqo-qcsd) | Modern Neqo fork and the QCSD runtime. |
| `legacy-neqo-qcsd/` (`legacy-neqo-qcsd/`) | Read-only published QCSD source used as behavioural authority. |
| `legacy-neqo-2020/` (`legacy-neqo-2020/`) | Read-only pre-QCSD Neqo parent used for historical comparison. |
| `QCSD.pdf` (`QCSD.pdf`) | Published QCSD paper. |
| `results.zip` (`results.zip`) | Browser-observed request-graph catalogue (SHA-256 `103a82cb95eaa305e38b0084ba16744429b273146be80ab05c7653d52bf66b11`) used to select preparation candidates; it is not a lab result or research corpus. |

The workspace root is not a Git repository. The lab and Neqo fork are separate
repositories, with Neqo pinned by the lab gitlink.

<a id="source-project-history-md-l62"></a>
## Provenance checkpoint

The execution checkpoint, including the active recovery acquisition source, is:

| Component | Identity |
|---|---|
| Modern Neqo base | `8a04d065c2d35c8e8fd804f91c7081ab6bb60b89` (`v0.30.0`) |
| Tagged published QCSD source | `39e293fb384dd341156eedd1e4b833d24904b1f6` (`usenixsecurity22-v1`) |
| Final research-execution lab | `a10abfb72cbd3766290081fb3c8b3177e7cc5999` |
| Documentation handoff lab | `9ed8dd9e965b0024a12708e337b39992e4cf0082` |
| Classifier POC preparation lab | `5f01abd8a3f41f1758ae17e5a6239c7ade315d0b` |
| Response-qualified capture-path lab | `76b395cb022b59783c21ef7328f571bfe1e48207` |
| Replacement workload preparation lab | `cee117d467799e042138a104f3aa32fa06e53417` |
| Serde workload preparation lab | `2a37ab6041fa6df3f2e8f435a18c9291b6ee9484` |
| Historical POC v1 response-qualification publication lab | `b3c7d07cec782847df248fcb542bb1bd8fb2a2b1` |
| Pre-recovery pinned Neqo fork | `f631ffa162ed05e3bc04d48beac771d53efef87a` |
| Pinned Neqo fork | `6aceaac85243d6e0e34354108e010705d3c83088` |
| Pre-replacement collection image | `sha256:b5d4099b39ab445d90a768ca97f7285793bdf7b17a91366c5a2f17872b18c16b` |
| Initial POC preparation image | `sha256:63234da6ec9162158004c5e1e88513aa2c67a0bcd262d5aba333f3d5d45502bf` |
| Historical v1 response-qualification preparation image | `sha256:0a0a5945c3dd88343191a5c913d851c6cc8bc64f1d48d05d23717bdaecdce835` |
| Research-smoke collection image | `sha256:4a92c724392b2f30e621cc7bf683fbb630acf71194f5f77d0414a06a24ebca23` |
| Research-smoke preparation image | `sha256:8060f3ad968193b1501c1efd502cf7a77980f293668f5efd52c8e1a1ab550d13` |
| Qualification-source lab | `a223cf89d3f8eb44c8cc05346b96c0583186aaa7` |
| Qualification preparation image | `sha256:b6de65763ab24f09a85faaa19c00daf3b72dcf68dd58cb973b98827dd022d487` |
| Earlier superseded POC v2 qualification-source lab | `9953cf3a9a29a2cb5f6aaf02439cd13f318b6b39` |
| Earlier superseded POC v2 publication lab | `88569f268260b36f0c4ccfc36681f7a42887b66c` |
| Earlier superseded POC v2 qualification-source Neqo | `a3bd748c1b3f4e24f7dc88f673365e6842db51a7` |
| Earlier superseded POC v2 qualification image | `sha256:c38afc629613bc8e7a5a82b55ad83a7e5787a51f780f14a199e9429be124ff43` |
| Superseded terminal-tail POC v2 qualification-source lab (Q1) | `2290b1f1a100d0d36f2d5ada405d9c26d382716d` |
| Superseded terminal-tail POC v2 publication lab (P1) | `d5543406359528b1382222d8ef3d3cffd67b7d4d` |
| Superseded terminal-tail POC v2 qualification-source Neqo (F1) | `867246557ec719fc34552b60abf624895be2706c` |
| Superseded terminal-tail POC v2 qualification collection image | `sha256:7b556344d65339e5cb399c37f7fe2a84ea248c9608e193f12269018c4ca47920` |
| Superseded terminal-tail POC v2 prepare/actual qualification image | `sha256:5d85e8d7d090e5a29e77fe5751c65c70299e2cf1fc709cb62c3fde50c16e191d` |
| Superseded terminal-tail POC v2 implementation-receipt aggregate | `33fe7032e9bf35efb7bb4d3d84b7e2733f4e81a455baef0df1df0120687e2c35` |
| Active response-qualification source lab (Q3) | `06cacddc21ab0ded9422d445723f60f37c530363` |
| Active response-qualification publication lab (P3) | `507cb04c38babcdc0050ddb064007a962efee0a2` |
| Active recovery acquisition-source Neqo (F3) | `6aceaac85243d6e0e34354108e010705d3c83088` |
| Active Q3/F3 qualification collection image | `sha256:bea517984b866d0c413ccc3d7c381e07a586a86eac5660717a9b8a809b4da382` |
| Active Q3/F3 prepare/actual qualification image | `sha256:227a931f5ae410fe298285d69a1d5d7b403ba026970949e5b30723d86b66b68a` |
| Active Q3/F3 qualification implementation-receipt aggregate | `558705bb0560ee3a87140670de7140ac087e9a0bf5ab13c1215f214f618f5ea4` |
| Active P3/F3 final collection image | `sha256:361ab7d677b1399bd0140f75d6cf7a9a30d350a7232fbd5529c1b2b9ddc000bd` |
| Active P3/F3 final prepare image | `sha256:db75500ff909ffae9fef32967820ec335fc880fb436c96f0db3a120a8911bce1` |
| Active P3/F3 final `source.json` SHA-256 | `590b4a856f7d8420329c90aba1d026edfcfbc75767ad9dc27fe75954c59f61dd` |
| Active P3/F3 final raw implementation-receipt SHA-256 | `c998823eb1b065e161e9397d079ff10155d0d55870580afe5efd058f9b03c1c4` |
| Active P3/F3 final execution implementation-receipt aggregate | `1115efbaca78ef8eab8bdf5551a598250a82af3812d3a23a2bee820ee600c1a6` |
| Superseded recovery acquisition-source lab (Q2) | `fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8` |
| Superseded response-qualification publication lab (P2) | `8a8d605166bfc27c6a7b8907162119e055ca7ca2` |
| Superseded recovery acquisition-source Neqo (F2) | `a8378520b9740be782bfe526cdb3eb05e6665571` |
| Superseded POC v2 qualification collection image | `sha256:29a6e0adaa65d88e1e30afd3722f20f976fe14ed0676fb28d0448ec9155c0700` |
| Superseded POC v2 prepare/actual qualification image | `sha256:ef5a3e7bcd20e8841f6c32064d40fcf94be48380f390146d5c039a49fc3665c0` |
| Superseded POC v2 qualification implementation-receipt aggregate | `a8384fd28e9b22c0a683138c0d7a039db3abf927bcc6bd15ffc936bdf2f352a0` |
| Failed-rehearsal P2/F2 final collection image | `sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122` |
| Failed-rehearsal P2/F2 final prepare image | `sha256:82434c67e194d29dc26c0cfa90014f01a2473c61ea92e9213c47ea1afc55297d` |
| Failed-rehearsal P2/F2 execution implementation-receipt aggregate | `7914466cbddff64dd8755eb06f664f3a6b1e667a0ec95c00cb7a3ad6d64dad72` |

The historical qualification image proves `lab_dirty=false`,
`neqo_dirty=false`, empty patch hashes, and runtime Neqo equal to its pinned
gitlink for the frozen v1 response sidecars. The two superseded v2 generations
likewise record their exact clean source, qualification images, and receipt
aggregates. Their images are evidence-generation history, not authorization for
new capture. Q2 deliberately contained no canonical response-store v2 files.
Its exact-five qualification succeeded atomically from Q2/F2, and P2 committed
those sidecars without alteration. The final P2/F2 images passed provenance,
implementation, campaign-preflight, and clock audits, but their rehearsal
sealed incomplete at 29/30. Q3 therefore removed that cohort and pinned the
readiness-starvation repair in F3. The new Q3/F3 transaction succeeded and P3
publishes it without alteration; the final P3/F3 images and exact-21 preflights
are complete. The first strict P3/F3 clock gate returned `NO_GO`, so those
images do not yet authorize capture. Authorization still requires a passing
repeat clock gate, a fresh excluded 30/30 rehearsal, and a verified interface
handoff.

<a id="source-project-history-md-l134"></a>
## Active workflow

The supported public commands are:

```text
./qcsd-lab build
./qcsd-lab prepare <id> <url> <approved-origin>...
./qcsd-lab derive-chaff-prefix-specs
./qcsd-lab qualify-chaff
./qcsd-lab qualify-response-chaff \
  getbootstrap-home-r3 cloudflare-quiche-r3 hyper-basic-client-r1 \
  serde-home-r1 rfc9114-text-r1
./qcsd-lab run <campaign.yml>
./qcsd-lab resume <result>
./qcsd-lab verify <campaign-or-result-or-artifact-bundle>
./qcsd-lab analyze <result>
./qcsd-lab fit <fitting-result>
./qcsd-lab test
./qcsd-lab test live
```

There are no capture-runtime `discover`, `probe`, `collect`, `dataset`,
classifier, projection, or split commands, and no `--dev`, `--dry-run`, or
`--resume` mode flags. `verify <campaign.yml>` is the non-executing preflight.
`resume` is its own command and continues only the frozen result supplied to
it. The separate `classifier-pilot` wrapper projects already sealed results;
it never performs capture or classification and cannot alter source evidence.

A campaign expands in one order:

```text
workload declaration -> request policy -> visit -> seeded defence order
```

Samples execute sequentially. Within one sample, Neqo may operate one
connection per distinct origin concurrently and may dispatch dependency-ready
requests according to the selected request policy.

<a id="source-project-history-md-l172"></a>
## Profiles

| Profile | Contract | Intended use |
|---|---|---|
| `live` | 1200-byte ceiling with deliberately bounded FRONT, Tamaraw, and event limits. | Controlled and reviewed-fixture smoke tests. |
| `research-1200` | Copies every non-size field from the tagged published source profile and changes only the common UDP ceiling and every defence packet-size field from 1450 to 1200 bytes. FRONT remains 900/1200 packets over 0.1–2.5 seconds; Tamaraw remains 5/20 ms with modulo 100; published Traffic Morphing, WTF-PAD, and Walkie-Talkie budgets remain intact. | Source-default-compatible 1200-byte research adaptation. This is explicit, not an implicit CLI default. |
| `published` | 1450-byte tagged-source settings. | Compatibility and controlled source comparison only. Running these values in modern Neqo against different workloads and networks is not an exact reproduction of the paper experiment or its results. |

`research-1200` is the profile for fitting, rehearsal, and final campaign
definitions. A 1201-byte schedule entry or fitted-artifact size is invalid for
that profile.

<a id="source-project-history-md-l184"></a>
## Defences and external inputs

Undefended, FRONT, and Tamaraw resolve completely from a profile. Static
replays a signed `seconds,signed_size` CSV. Traffic Morphing, WTF-PAD, and
Walkie-Talkie require learned JSON structures.

[`static-control-1200.csv`](../../config/defense-params/static-control-1200.csv)
is a mechanical integration control with four alternating 1200-byte events at
25, 30, 35, and 40 ms. The 25 ms startup lead lets the asynchronous client
provision its chaff stream before the first exact slot. The control proves
schedule loading, direction handling, and the common size ceiling. It is not
fitted and is not evidence of defence efficacy.

The checked-in `*-live.json` files and their receipts are reviewed smoke
fixtures only. They cannot be used by fitting or evaluation campaigns.

<a id="source-project-history-md-l200"></a>
## Workload catalogue and cohort freeze

`results.zip` (`results.zip`) contains 17 Chromium-observed request graphs from
the retired discovery workflow. Its JSON files may include historical replay
and header-policy fields. Those fields are catalogue metadata only; the files
are not accepted campaign workloads and are not active result formats.

`prepare` is the only promotion path. It applies an explicit origin allowlist,
removes unsafe inputs, performs three cooldown-separated undefended Neqo
stability runs, freezes exact safe request headers and dependencies, and writes
one `config/workloads/<id>.json`. The whole-file SHA-256 recorded below is its
preparation receipt.

The earlier `-r1` preparations were retired from research use after a
case-insensitive Chromium-header merge defect was found. The `-r2` generation
was then retired because its receipts did not qualify the complete packet
ledger, including handshake traffic, against the absolute 1200-byte ceiling.
Fresh preparation from the corrected clean image froze this `-r3` adaptation
cohort:

| Workload | Resources | Preparation receipt SHA-256 |
|---|---:|---|
| Bootstrap Home (`getbootstrap-home-r3`) | 9 | `863638bb6bf7a27c2a4e9184dcb9c3db8d748af1e0da1b875d24a21233b92ca2` |
| Bootstrap Introduction (`bootstrap-introduction-r3`) | 9 | `e228029e7c987c63f8218e5471375e62e6d4557825bc6c4c0cb4bbfa0be6c16b` |
| Apache Traffic Server docs (`apache-traffic-server-docs-r3`) | 18 | `8f4fa9b10c4488ff99d30e7ac8b2b784867416c84635afe96b9c4ef45ab71ecd` |
| NGINX QUIC (`nginx-quic-r3`) | 11 | `56ddd2eee52affc59d0062c83b49e2fd435d0fe9ca40f4f0b30e65c156e7ef09` |
| Cloudflare QUIC (`cloudflare-quiche-r3`) | 1 | `e608366c95d6902234b4a705043435b3868f9572bcb8e103feb71db3110cbacc` |
| nghttp2/ngtcp2 (`nghttp2-ngtcp2-r3`) | 8 | `a871e1d783b52a79fb1f72761ea2771fced38ba408fbed0896a3c280d20927f1` |

All 18 stability runs recorded zero UDP payloads above 1200 bytes over their
complete packet ledgers. The final preparation pass retained these rejection
records:

| Candidate | Rejection |
|---|---|
| Behance | Whole-capture UDP payload maximum was 1452 bytes. |
| Chromium project pages | A pre-handshake Initial datagram was 1280 bytes. |
| aioquic | The endpoint refused the preparation connection. |
| Guardian | Whole-capture UDP payload maximum was 1280 bytes. |
| R10 | Exact response identity was unstable across the three runs. |
| TeamViewer | Retained assets were orphaned from the source/final navigation root. |

NGINX QUIC and Bootstrap Introduction passed the unchanged preparation gate
and were promoted. No failed or legacy manifest was substituted. The cohort
contains six unique request graphs over five distinct origins; Bootstrap Home
and Bootstrap Introduction share an origin and many static assets. That
correlation can reduce their fitted distance or mould-padding cost, so the
resulting cohort is explicitly a reproducible QCSD adaptation, not six
independent websites or a representative sample of the rejected population.

Fitting used all six frozen workload definitions; the post-fit smoke selected
two members of that cohort. For those shared workloads, fitting requests and
captures were not reused as evaluation visits, and no evaluation observation
influenced a fitted artifact.

There are no monitored/unmonitored roles or open-world views in the active lab
specification. The five-class POC adds a strictly closed-world, offline handoff
contract: domain labels and train/validation/test/inference roles are derived
only after sealed acquisition. Fitting and evaluation separation is otherwise
expressed by separate campaigns, independent visits, and the sealed
source-result receipt.

<a id="source-project-history-md-l262"></a>
## Active classifier POC cohort and response qualification

The advisor POC uses five distinct single-origin workload/class bindings:

| Workload | Class label | Resources | Prepared-manifest SHA-256 |
|---|---|---:|---|
| `getbootstrap-home-r3` | `getbootstrap.com` | 9 | `863638bb6bf7a27c2a4e9184dcb9c3db8d748af1e0da1b875d24a21233b92ca2` |
| `cloudflare-quiche-r3` | `cloudflare-quic.com` | 1 | `e608366c95d6902234b4a705043435b3868f9572bcb8e103feb71db3110cbacc` |
| `hyper-basic-client-r1` | `hyper.rs` | 5 | `e2237d2ac033df287ede201fdf72d89c3e3e117dbf63e4bade89a338c88d673b` |
| `serde-home-r1` | `serde.rs` | 20 | `bbc32546f77fbcd4204ffdc746492adb68830975f0c129fcda56cffec7302eb5` |
| `rfc9114-text-r1` | `www.rfc-editor.org` | 2 | `379ad9082425c7a3e31334de493a4d77d610bb68c4b322b3bc0ac8c41588f9ce` |

The RFC 9114 text workload is active. The separately prepared 22-resource Haxx
graph `http3-explained-en-r1` remains unused: it is not referenced by the
rehearsal, any formal campaign, the response-qualification cohort, or the
classifier handoff.

FRONT and Tamaraw require no fitted corpus. The current POC contract requires a
create-only five-file response transaction under
`config/chaff-response-qualification-store/v2/`. Q3 deliberately removed the
superseded P2 files and pinned F3 before the replacement qualification. That
exact-five transaction has now completed atomically, and P3 publishes its
untouched output as the active canonical v2 cohort.

The separate chaff request copies the prepared resource's `Accept` and
`Accept-Language` exactly and forces `Accept-Encoding: identity`; application
workload requests are not changed. Eligible known-valid same-origin candidates
with at least 1,200 prepared body bytes are tried in deterministic
descending-body-size, resource-ID, and URL order.

Each candidate must complete three independent connection epochs separated by
at least 30 seconds. One connection per epoch issues 40 requests in eight
sequential waves of at most five concurrent requests, yielding 120 completions
per candidate. Every completion must share an exact successful
identity-encoded status, body length, and body SHA-256. Only an identity or
capacity rejection advances to the next candidate; transport, DNS, timeout,
and protocol failures abort the atomic transaction. Each published v2 file is
sidecar schema 2 and derives a schema-4 response-only runtime manifest.

The active transaction was qualified from clean Lab Q3
`06cacddc21ab0ded9422d445723f60f37c530363`, clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`, qualification collection image
`sha256:bea517984b866d0c413ccc3d7c381e07a586a86eac5660717a9b8a809b4da382`,
and prepare/actual qualification image
`sha256:227a931f5ae410fe298285d69a1d5d7b403ba026970949e5b30723d86b66b68a`.
The qualification build-tag suffix was
`q-06cacddc21ab-6aceaac85243-20260815T211610Z`.
Every sidecar binds qualification implementation aggregate
`558705bb0560ee3a87140670de7140ac087e9a0bf5ab13c1215f214f618f5ea4`.
All five deterministic first candidates (`candidate_index: 0`) qualified.
Across 15 independent connection epochs, `5 × 3 × 40 = 600` stable identity
completions produced 61,875 packet observations: 54,573 incoming and 7,302
outgoing. Within every workload, consecutive epochs retained at least the
required 30-second gaps; the maximum observed UDP payload was 1,200 bytes, and
no oversized packet was observed. P3
`507cb04c38babcdc0050ddb064007a962efee0a2` atomically publishes these active
hashes:

| Workload | Active P3 v2 sidecar SHA-256 | Active P3 schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `9b868b3b083c3acca66d6d05c7c9962e3aad28750defbdbe21a340fb054c1148` | `7fb560f246c90b2ad3eaf937f7a97f3bf9661f244fd10fd84e86753db51ddf3d` |
| `cloudflare-quiche-r3` | `c9dacbabdd2861c5ef505fa572f7f1b9407084c7002a5ef28057b66c12788246` | `51e90afbd48747f9a776eeb9fb80158b38f4a909d9fd35932ceb4c7fb1edd80a` |
| `hyper-basic-client-r1` | `92b5090ba4b4d228db652f7d435da3d29867f9ffe221a835e4f6d965cd6840d9` | `2fa47f098191f2c72f9abcf90b4b2f7b0edef1d21bc480c93fc18f5f988df514` |
| `serde-home-r1` | `19fa46e8da00b6af47090ae9857335b9db966a3b55dc9c0592059cdceb2eafc4` | `d463076c6baf2a01fd94d534fae8015f99d523a54ebd4a9dc9d95d4109cf1f11` |
| `rfc9114-text-r1` | `f43285364a01de0f5024632995b83f034911c5d3c7c5770396b240f07c5fcf62` | `0152f1137aa31e5371ad4792829485710cb9218192cf115bc7bbdfa0a26ae797` |

P3 has tree `a600c16c2ef71852ec4002c10f1a09ac03f84280` and parent Q3. The
immutable final collection image
`sha256:361ab7d677b1399bd0140f75d6cf7a9a30d350a7232fbd5529c1b2b9ddc000bd`
and final prepare image
`sha256:db75500ff909ffae9fef32967820ec335fc880fb436c96f0db3a120a8911bce1`
were built from clean P3/F3 under build-tag suffix
`p-507cb04c38ba-6aceaac85243-20260815T215336Z`. Their `source.json` hashes to
`590b4a856f7d8420329c90aba1d026edfcfbc75767ad9dc27fe75954c59f61dd`,
the raw implementation receipt hashes to
`c998823eb1b065e161e9397d079ff10155d0d55870580afe5efd058f9b03c1c4`,
and the execution implementation-receipt aggregate is
`1115efbaca78ef8eab8bdf5551a598250a82af3812d3a23a2bee820ee600c1a6`.
Two independent audits confirmed exact clean provenance, baked/runtime
identity, implementation receipts, and the expected 13-layer common prefix
plus one preparation layer. All 21 campaign plans preflighted exactly: the
30-sample rehearsal, ten 100-sample baseline plans, and ten 150-sample paired
plans expand to 2,530 planned captures with unique execution IDs and seeds;
the focused deterministic contract suite passed 72/72 tests. These are
readiness checks, not executed rehearsal or formal samples.

The first strict P3/F3 cross-clock gate sampled one persistent Windows QPC
source 969 times over a 241.9607826-second QPC span and returned `NO_GO`.
Linux monotonic/QPC was `1.000151908954439` endpoint and
`1.0001434526737227` OLS, both above the strict `1.0001` ceiling, even though
raw/QPC passed (`1.0000075117545102` endpoint and
`1.0000000385145573` OLS). The maximum absolute Linux/Windows offset was
13.140992 ms, also above its 10 ms bound. The sample stream hashes to
`37f5083cd69c963b3461cc48ff65fc5ce698e536dd22254548d5d172070cd12c`.
Post-gate `adjtimex` reported `TIME_ERROR`, `STA_UNSYNC`, and 16,000,000 us
maximum error while WSL `NTPSynchronized=no`. A read-only settle watch from
22:25:14Z to 22:34:18Z found repeated `TIME_ERROR`/`STA_UNSYNC` transitions and
monotonic/raw rates from about +134.5 to +155.1 ppm with no convergence. It was
stopped without changing the clock or time services. A clean WSL
shutdown/relaunch and a fresh passing preflight are required before retrying;
no rehearsal, handoff, or formal campaign was launched.

After a true Windows restart on 2026-08-18, one separately labelled diagnostic
gate used one persistent Windows process for 969 QPC/UTC samples over
241.9708647 seconds. Every original quantitative bound passed: monotonic/QPC
was `1.0000953573606004` endpoint and `1.0000714157302715` OLS, raw/QPC was
`1.0000225122144633` endpoint and `1.0000002382675017` OLS, the maximum adjacent
realtime-minus-monotonic phase change was 8.330056 ms, and the maximum absolute
Linux/Windows offset was 8.789336 ms. Both pre/post `adjtimex` states were
`TIME_OK`/status zero and W32Time remained Running/Automatic, leap zero, stratum
five, and last-sync-error zero. The canonical diagnostic sample stream hashes
to `ed7aa197cbd324e7ae07866660c69fcb1e9f0040163af8f0f918015158d29540`.

That diagnostic also observed 143 transient WSL `TIME_ERROR`/`STA_UNSYNC`
samples without a corresponding numeric threshold violation. Because WSL boots
with Hyper-V implicit time synchronization and the original accepted clock gate
did not treat intermediate kernel status as a standalone numeric measurement,
the rule for the next, separate gate is declared before it runs: pre- and
post-gate `adjtimex` must both be `TIME_OK` with status zero; W32Time and the
clocksource must remain unchanged and healthy; every original rate, phase,
cross-wall, span, process, and pairing bound must pass unchanged. Every rolling
30-second monotonic/QPC and raw/QPC endpoint and OLS ratio must also remain in
`0.9999..1.0001`, preventing a balanced whole-window result from hiding local
slew. Intermediate status is advisory only when it is exactly
`TIME_ERROR`/`STA_UNSYNC (0x40)` and all other requirements pass; its sample
count, duty cycle, and contiguous transition segments must be reported with the
canonical sample digest. Any other status bit/state, numeric failure, or
endpoint-status failure remains `NO_GO`, and a passing result must be described
as having observed a transient advisory rather than as continuously
synchronized. The diagnostic itself does not authorize traffic.

The following separately acquired official prospective gate also sampled one
persistent Windows process 969 times over 241.9734178 seconds. Its canonical
sample stream hashes to
`af495806f5777c06e95e18c1f7d64ef654852f84b5af132684cf0b3b52fc0d1c`.
Whole-window ratios, phase, and cross-wall checks passed, but the frozen rolling
checks did not: five 30-second monotonic/QPC endpoint windows failed, reaching
`1.000211077624527`, and three raw/QPC endpoint windows failed, ranging from
`0.9998903756073716` to `1.0001438230244404`. All corresponding rolling OLS
checks passed. The run observed 98 exact advisory
`TIME_ERROR`/`STA_UNSYNC (0x40)` samples in seven contiguous segments; pre/post
Linux timex endpoints were `TIME_OK`/status zero. W32Time nevertheless ended
with last-sync-error 2 (`stale time data`), which independently violates the
frozen healthy-endpoint rule. The gate therefore returned `NO_GO`. No Docker
campaign, packet capture, rehearsal result, or handoff was created.

The superseded P2 transaction was qualified from clean Lab Q2
`fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8`, clean Neqo F2
`a8378520b9740be782bfe526cdb3eb05e6665571`, qualification collection image
`sha256:29a6e0adaa65d88e1e30afd3722f20f976fe14ed0676fb28d0448ec9155c0700`,
and prepare/actual qualification image
`sha256:ef5a3e7bcd20e8841f6c32064d40fcf94be48380f390146d5c039a49fc3665c0`.
Every sidecar binds qualification implementation aggregate
`a8384fd28e9b22c0a683138c0d7a039db3abf927bcc6bd15ffc936bdf2f352a0`.
All five deterministic first candidates (`candidate_index: 0`) qualified.
Across 15 independent connection epochs, `5 × 3 × 40 = 600` stable
identity completions produced 62,007 packet observations. Within each workload,
consecutive epochs retained at least the required 30-second gaps; the maximum
observed UDP payload was 1,200 bytes, and no oversized packet was observed. P2
`8a8d605166bfc27c6a7b8907162119e055ca7ca2` atomically published these now
superseded hashes:

| Workload | Superseded P2 v2 sidecar SHA-256 | Superseded P2 schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `4b63acf9dfa58413500cf8eaa34fc326a71a74d6c5df3404378543ea5ae707cf` | `c2dc6643caa028e137d717adf4fc13561b1e3c07bfbad28bef2267c0ed20fc92` |
| `cloudflare-quiche-r3` | `5728dda8668bc4aca816495d87c56038a7ed267b3e902518cdd7bd84b990c3d2` | `0b7794ebdf2155901f7398c95602e111e27087ce5f945a22b198391aa1054277` |
| `hyper-basic-client-r1` | `e30e877f068a199688948357b19c61803f94cad57123382e79812492750ab55e` | `7b5a2755a6bf47010289df74d40dc45aeaf58c30dd2a8ce32fc928eaa7b70332` |
| `serde-home-r1` | `86b6d3fcdc208e50b71e5cf957770a9e6319dae39a2e87b9d884f713c0ec3da4` | `e433468dcfee5c2ff6de7d4376588e7c104f60d13977894412ee58a04c88a212` |
| `rfc9114-text-r1` | `e55414ca9da748f17b89c02d762b1ac39f74acb349ed60d67833c1d5999e627b` | `20ce6ddd56b4684179c0cec8cac12bcef7ce8ef9327d954c2ecfe2239ec84bd9` |

The final collection image
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`
and final prepare image
`sha256:82434c67e194d29dc26c0cfa90014f01a2473c61ea92e9213c47ea1afc55297d`
were built from clean P2/F2. The final execution image reports
implementation-receipt aggregate
`7914466cbddff64dd8755eb06f664f3a6b1e667a0ec95c00cb7a3ad6d64dad72`.
All final-image provenance, implementation, baked/runtime, 21-campaign
preflight, and strict clock audits passed. The subsequent rehearsal sealed
valid but incomplete at 29/30, so these images are excluded and formal capture
is not authorized.

The most recent historical transaction was atomically published from clean Lab
Q1 `2290b1f1a100d0d36f2d5ada405d9c26d382716d`, Neqo F1
`867246557ec719fc34552b60abf624895be2706c`, qualification collection image
`sha256:7b556344d65339e5cb399c37f7fe2a84ea248c9608e193f12269018c4ca47920`,
and prepare/actual qualification image
`sha256:5d85e8d7d090e5a29e77fe5751c65c70299e2cf1fc709cb62c3fde50c16e191d`.
Every sidecar binds implementation aggregate
`33fe7032e9bf35efb7bb4d3d84b7e2733f4e81a455baef0df1df0120687e2c35`.
All five deterministic first candidates
(`candidate_index: 0`) qualified, yielding `5 × 3 × 40 = 600` stable identity
completions. Each epoch used eight waves of five requests (`8 × 5`), the epochs
retained their 30-second gaps, and all epoch receipts report a maximum UDP
payload of 1,200 bytes and zero oversized packets. F2 changes the qualified
implementation, so this Q1/F1 transaction is superseded and cannot authorize
new capture. Its historical hashes are:

| Workload | Superseded terminal-tail v2 sidecar SHA-256 | Superseded schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `0bef93532273f59718e1fc4123eccfa6833922ff34f0d22cc9cf6cf03963cb5d` | `f411d539e656a5abd6a49c94da5a60d4e2898f141b1ebf86e48b2d2bd2ca4372` |
| `cloudflare-quiche-r3` | `d9dc5898464e7cb05f37fe9faf758250a72eaf14209913d7f2e56ffd31ced6ac` | `5d51d0f68d67c1847f49df01640c0ea6ca0a303dc3b567a4dc81f1ed5aef190a` |
| `hyper-basic-client-r1` | `4f8f51722d0c9a3d1d696f845bf2ee91ff45f3387b62c472115f682b5c353428` | `3fc7f34b90e9cbc423dc1f727bf157c5b3910b30bb61c2a52eef7a74cebf8a55` |
| `serde-home-r1` | `ee1f97b15a4f93702eda6c98b6578a2eb958df6f0f6a5129ab6b0a9d27ce3ca1` | `edb21e2792dfe59dd0c30f586709e5310e5b6ba5744a0c0a5ce334bd7746f797` |
| `rfc9114-text-r1` | `1d75fcf42ba170eabe76f5184adcc9551a4b3360d3e869f694108055360541af` | `e9dfb138adbdb18d43bf2c70eb34240dc54894a8e58aa1766853e4fbfdf178b6` |

Those exact files remain recoverable from Lab publication P1
`d5543406359528b1382222d8ef3d3cffd67b7d4d` and their frozen sealed results.
Those superseded bytes were removed from Q2 rather than mixed with F2
evidence; P2 contains only the independently qualified replacement cohort.

An earlier v2 transaction was published from clean Lab
`9953cf3a9a29a2cb5f6aaf02439cd13f318b6b39`, clean Neqo
`a3bd748c1b3f4e24f7dc88f673365e6842db51a7`, and qualification image
`sha256:c38afc629613bc8e7a5a82b55ad83a7e5787a51f780f14a199e9429be124ff43`.
Its historical hashes remain:

| Workload | Earlier superseded v2 sidecar SHA-256 | Earlier superseded schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `37e5e6933b337872b49889886e5930f3aa1a7778032bc9ed85a0372885e8e95d` | `330a8d41db984fc43c0c324e091cfba2906871a47ee06d7fb9c2de0aac1db32a` |
| `cloudflare-quiche-r3` | `e8fe81526aec5fa9af2c1c03ad4f093732ecc738a02bd2dd997104dc253a1957` | `38dfa66be8b0a55857845853c237a37014fe47095328d8d32187871277c3ac3e` |
| `hyper-basic-client-r1` | `816d6bcc0c43cf0d672fc0f21cc0dd871d80fa9ca24ebcadcbc81b48d33a3bed` | `ffc24029a219246cd40060cd70953e4cf0a3590e59a700ec6c6f72ce7800b54d` |
| `serde-home-r1` | `46abffb21b7f93ebe328f56ad82819fcced1586aa3966de2d733fa7a5133018f` | `91ad7a33ed70cfcf4bc1b062e747b1371bad00ca16171ee3539f40755f18c9d3` |
| `rfc9114-text-r1` | `d76a4ff366a6b8dce65b42cca02d2a55c6333e649b28316fcdfe58b060d34c2f` | `9fb65d16532ff6290aa530e4829f87167cd784a30bfb68e5d7d921acd5da8fc5` |

Those superseded files remain recoverable from Lab commit
`88569f268260b36f0c4ccfc36681f7a42887b66c` and frozen sealed results.

The frozen historical response-store v1/schema-1 sidecars remain available for
verification compatibility:

| Workload | Historical v1 sidecar SHA-256 |
|---|---|
| `getbootstrap-home-r3` | `d5f61f383f0e8710eb90b973a07ae45c4d7116a741a7ee00b71b11970b5485bf` |
| `cloudflare-quiche-r3` | `ffeac8a6620f6e91885403218b5bc4baef2be69c2fa64cca9c61293b49c0c14a` |
| `hyper-basic-client-r1` | `ed27a6a023e3c1f979eee8e23286024b706dcd9d9c6eea6e73925aaa8113ed66` |
| `serde-home-r1` | `79c1a716c1e71b181492fe8d4c212177c0df74a94808ffa975c5703e16cb15be` |
| `rfc9114-text-r1` | `336238f6b3fb933246d472979357fef57db78171273b3a1815ba9b22f444623a` |

Those historical sidecars record three independent unshaped invocations of
five parallel requests and derive schema-3
`qcsd-qualified-chaff-manifest` values with
`qualification_scope: response-only`. They remain valid for their frozen
historical results, but they are not the active POC recovery cohort; frozen
loading rejects a mixture of schema-3 and schema-4 manifests. Neither version
contains a Walkie-Talkie prefix specification or fitting field. This narrower
route is permitted only when every defended kind is FRONT or Tamaraw.
Baseline-only campaigns need no chaff qualification, and any campaign
containing another defence still takes the separate full-v2 route.
Qualification traffic is never a classifier sample.

<a id="source-project-history-md-l513"></a>
## Full-v2 qualification bindings for broader defences

The atomic exact-six qualification was produced by the clean qualification
image recorded above. `Q` is the qualified parallel response count and `S` is
the exact one-shot Walkie-Talkie stream cohort. The current raw hashes are:

| Workload | Q/S | Prefix spec | Qualification sidecar | Derived manifest |
|---|---:|---|---|---|
| Apache Traffic Server | 5/4 | `90997eccad7a4c6567fc8ce2380df798db396b2e1963aa522f70cbd09e08c57f` | `418747b2982e405b3da96711105119936a066e226243b658edc7831122a14413` | `1ec8fc1b6a2c8b4438eb49c45e72a7ba13e4ffc2a70b1b246d4e5af5480aa089` |
| Bootstrap Introduction | 5/3 | `538e680b8b6040b1b92010e8560f184e853d4c08d4e2f148d90c0cf7bb40ebb7` | `e98c767b05d8c494072cad5287b4c3b91a2259950c8edb9377fa938afd5ef9be` | `e64122086918861f29976a5653084a040434805ced031772b4b8ecc6140c336d` |
| Cloudflare QUIC | 6/6 | `b2440fa667b58e1cb975432650392483582859b94cc3dc99d92bac22545b72dd` | `f08568f482758aac046a3f61811d390248a872ff2cec8b149326a6b8cea154ae` | `9a2faf90021c796e2e19281a51bc18f637d8fb5c08c0909b7b9c6c03fb974d09` |
| Bootstrap Home | 5/3 | `a8fb2448a15005d856a57d18c28444511a70fe7a367d2e0941cb60cf913f3893` | `b0de9b24ee1c84931508b53c767d998bb9c5b82cbcf9ff5f2efee5a3a671ffe8` | `8c78a0e615f348dc902e3d81d94e063326e37a1cc466f974ff719d32876b486d` |
| nghttp2/ngtcp2 | 5/4 | `a411a4a6a9dd923fde39f5895aedc036d476610ba326ef8ea258dd2ded623926` | `1bf37141647b4fce0c8b4bf41b7e3a67d46a463a45b5bc0e8ddb253c4dcf8c3e` | `e7003bdb2e5d6eb4a0024db2af0bf4e8ddb08297e0f7ac1cfd68f66fb3c11366` |
| NGINX QUIC | 20/20 | `4900396a0769244bf0320312d9f85a64a3f1319fa33f083a7139ab0046976338` | `06ea5daab06efb7bb6b6b47cfecb870138910116f1cd8030ee39c199a8137b89` | `928e268202a51357cdbf267b50e9d331f32caf82e625d968e56b87c28f7122e0` |

<a id="source-project-history-md-l528"></a>
## Fitting and sealed artifact bundle

The fitting workflow is exact and create-only:

1. Freeze six prepared workloads.
2. Run a `purpose: fitting`, `profile: research-1200` campaign containing
   exactly those six workloads, ten visits each, request policies in exact
   `as-defined`, `half-duplex` order, and only the undefended baseline.
3. Verify the resulting 120 eligible samples and its evidence seal.
4. Run `./qcsd-lab fit <fitting-result>`.
5. Verify the generated bundle with
   `./qcsd-lab verify artifacts/research-1200`.

`fit` first verifies the complete source result, then deterministically creates:

```text
artifacts/research-1200/
  traffic-morphing.json
  wtf-pad.json
  walkie-talkie.json
  provenance.json
```

`provenance.json` is one common receipt. It binds the `research-1200` profile,
1200-byte ceiling, source result and evidence identities, all contributing
samples, fitting decisions, exact workload coverage, and SHA-256 of the three
runtime files. It contains no timestamp or absolute path. An identical rerun is
idempotent; different content at the fixed destination is a collision error.
The source result is never modified.

The sealed fitting result is
`results/research-fitting-1200/20260812T130241.322364Z`: all 120 samples are
accepted and eligible. Its deterministic four-file `artifacts/research-1200/`
bundle verifies against that result. Its raw SHA-256 values are:

- provenance: `38303c58933d60f9cdb37ced51d9bfab4f3553aaad1680c3f042d9c61ce73a61`;
- Traffic Morphing: `ad278bd31428419b6d402aa30fab041005ada8b48f8d07a6a1641635c90d935c`;
- Walkie-Talkie: `5e0084cdb0ed8f7c0a56d18442d971ce79042f3ab4a2630c341548e21ae97b97`;
- WTF-PAD: `59433577582f8ee89c39aa7649d96d1fd83d13abe6891a0046827f6a055f3dd6`.

<a id="source-project-history-md-l568"></a>
## Research campaign sequence

| Gate | Exact expansion | Current state |
|---|---:|---|
| Fitting | 6 workloads × 2 policies × 10 visits × undefended = 120 | Complete: 120 accepted and eligible; fitted bundle verified. |
| Post-fit smoke | 2 workloads × 1 policy × 1 visit × 7 modes = 14 | Complete: 14 accepted and eligible, zero failed; verified and analyzed. |
| Superseded six-workload pilot attempt | 6 workloads × 1 policy × 1 visit × 7 modes = 42 | Sealed incomplete diagnostic: 31 accepted, 27 eligible, 11 failed; excluded from classifier handoff. |
| Classifier POC rehearsal | 5 classes × 1 policy × 2 visits × 3 modes = 30 | P2/F2 sealed valid but incomplete at 29/30 and is excluded. P3/F3 qualification, final images, and preflights are complete, but the strict clock gate is `NO_GO`; the fresh 30/30 rehearsal and handoff are unrun. |
| Classifier POC formal corpus | 5 classes × (300 undefended + 100 FRONT + 100 Tamaraw) = 2,500 | The old-source baseline-01 completed 100/100 and paired-01 stopped at 146/150; both are excluded diagnostics. The homogeneous P3/F3 corpus is unrun and remains blocked by the clock, rehearsal, and handoff gates; it must restart at baseline-01. |
| Historical engineering rehearsal | 6 workloads × 1 policy × 1 visit × 7 modes = 42 | Remains on hold. |
| Historical engineering final | 6 workloads × 1 policy × 3 visits × 7 modes = 126 | Remains on hold. |

The checked-in smoke is `research-smoke-1200`, seed `2026081204`, over
`cloudflare-quiche-r3` and `bootstrap-introduction-r3`. It consumed the verified
production fitting bundle while collecting new visits. The completed result is
`results/research-smoke-1200/20260814T023209.708923Z`: all 14 samples were
accepted and eligible on attempt one, official verification reports 104
authoritative files, and analysis produced 14 summary rows and six SVGs. The raw
SHA-256 values of `evidence.sha256` and `experiment.json` are
`59371aedf7dfa7ce289cce25766af763ede405d2f62527dc16c0d7882b42203a`
and `1cd8c415751736aa43677fac67f1bea666b941a47ae90d3658bf7cb2bf17d248`.
The defended local gate was:

```shell
./qcsd-lab test live
```

The first public-Internet research capture was the fitting campaign; the
external smoke then used independent evaluation visits. The superseded runtime
failures are locally preserved and manifest-sealed at
`results/chaff-qualification-diagnostics/q7-b19cb04-7ebcdb0-schema6-203eee42-runtime-falsification/`
with outer-manifest SHA-256
`4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9`.
The attempted six-workload classifier block is preserved at
`results/research-classifier-pilot-01-1200/20260814T064655.275845Z` as bounded
diagnostic evidence. It is not a valid block or training corpus: 31 of 42
samples were accepted, 11 failed, and only 27 were eligible. Its failures
recorded a broken WSL capture clock and workload-specific response/fidelity
gate rejections, so blocks 02--07 were never launched. That bounded diagnostic
does not, by itself, establish a general underlying defect in Neqo.

The replacement POC follows the advisor-approved closed-world protocol. Its
five labels are `getbootstrap.com`, `cloudflare-quic.com`, `hyper.rs`,
`serde.rs`, and `www.rfc-editor.org`, bound respectively to
`getbootstrap-home-r3`, `cloudflare-quiche-r3`, `hyper-basic-client-r1`,
`serde-home-r1`, and `rfc9114-text-r1`. Each runnable graph is single-origin.
The two unfitted defences are FRONT and Tamaraw; the classifier is trained and
tuned only on undefended observations. Per class, undefended observations
split 240/30/30 by temporal acquisition block into train/validation/test, while
all 100 FRONT and 100 Tamaraw observations remain inference-only. This can
measure degradation of an undefended-trained classifier under these fixed
defences; it does not test an adaptive attacker, an open-world classifier, or
generalization beyond the five frozen graphs.

The formal acquisition consists of ten ordered temporal blocks. Every block
contains one 100-sample baseline campaign (20 undefended visits per class) and
one 150-sample paired campaign (10 visits per class under undefended, FRONT,
and Tamaraw). Odd blocks run baseline then paired; even blocks run paired then
baseline, and both results finish before the next block starts. Blocks 01--08,
09, and 10 supply the undefended training, validation, and clean-test roles.
The 30-sample rehearsal and its interface handoff are explicitly excluded from
all 2,500 formal observations. It is a strict go/no-go gate: proceed only with
exactly 30/30 accepted and eligible samples and a verified interface handoff.
The collision-free, create-only destinations reserved for the new lineage are
`classifier-poc5-rehearsal-v2-p-507cb04c38ba` for the rehearsal and
`classifier-poc5-v2-p-507cb04c38ba` for the eventual formal export. Both
destinations and their staging prefixes were confirmed absent; the existing
generic historical rehearsal handoff is preserved and will not be overwritten.
Neither new destination has been created.
The most recent pre-F2 rehearsal is
`results/research-classifier-poc5-rehearsal-1200/20260815T132537.356504Z`.
It is valid and complete: all 30 samples were accepted and eligible, there were
zero terminal failures across 33 attempts, and the interface handoff verified.
The raw SHA-256 values of its `evidence.sha256` and `experiment.json` are
`350e015f97d49fa8c14f7e5d82489b05f2fbdd5d0cb9a0345b54abba32d9b560`
and `f3028b05a7908826b003fafb8e07bdd0d0a709a183be0513fa7cc5efb7eb2703`;
the handoff's `SHA256SUMS` hashes to
`392d897369de9e38bbdae116b79c1559a9f5d00a65f33c4b8eccbb887053e02c`.
That gate bound clean Lab P1 `d5543406359528b1382222d8ef3d3cffd67b7d4d`,
Neqo F1 `867246557ec719fc34552b60abf624895be2706c`, and collection image
`sha256:5d56c63fdd182ba311392602bad77e8f4c3198c6bd08958a691cac197f74f05e`.
It remains strictly excluded from classifier input, and its source-specific
authorization is superseded by P2/F2 and the new final-image lineage.

Formal acquisition began under that old authorization. Baseline-01 at
`results/research-classifier-poc5-baseline-01-1200/20260815T134617.090622Z`
is valid and complete with 100/100 accepted and eligible samples and zero
failures. Its `evidence.sha256` and `experiment.json` hash to
`65a858a25a714a534dff1afb7ec57d510fd2ac8ea6b1995b9aad34fd94136bc9`
and `5ae8cded5a7dc117ec21ce302a9a1b12051acc8690939a75fbbe004f76fd593b`.
Paired-01 at
`results/research-classifier-poc5-paired-01-1200/20260815T144004.646818Z`
is valid but incomplete: 146/150 samples were accepted and eligible and four
FRONT samples failed terminally. Its corresponding hashes are
`dc1b656a8745d589ff43224862647d46aed67d8cf3687d1d7cd78e7e84ffb2af`
and `767d0237d3172b506d951bdb9a9c1c4b37df6aee3e166d90b9193c3d7c9ab7d2`.
Both results bind the same P1/F1/image receipt as the rehearsal. They remain
immutable diagnostics, but neither may be mixed into the future P3/F3 corpus;
all twenty formal campaigns must restart from baseline-01 under one new
homogeneous source receipt.

The first P2/F2 rehearsal is preserved at
`results/research-classifier-poc5-rehearsal-1200/20260815T201524.981071Z`.
Official verification reports a valid but incomplete seal: 29/30 samples were
accepted and eligible, one Hyper visit-0 FRONT sample failed all three automatic
attempts, and 223 authoritative files remain checksum-closed. The SHA-256 values
of `evidence.sha256` and `experiment.json` are
`3d9baba02bb87e3e884992c1a215dcb549b8f1628b732826a5b502669e496df7`
and `c9544d06a4349f5160388fb93f7ea8b9be7c5f80435668ef0dd66360379978ff`.
All 29 accepted samples passed exact response identity, zero-miss schedule,
receive accounting, capture, UDP, and constant-offset clock gates. The three
failed Hyper attempts transmitted and peer-acknowledged all request streams,
but a stale fixed-incoming controller deadline caused an await-free runner loop
to starve Tokio socket readiness while the response waited in the kernel. This
is an excluded implementation diagnostic, not authorization for formal capture.

F3 `6aceaac85243d6e0e34354108e010705d3c83088` repairs both halves of
that starvation signature without changing strict schedule windows: fixed
reconciliation advances the incoming retry watermark while retaining exact
event processing, and an already-due runner wake performs one readiness-aware
await instead of an await-free loop. Its exact-base regressions fail on F2 and
pass on F3; all relevant full suites and independent audits pass. Q3
`06cacddc21ab0ded9422d445723f60f37c530363` pins F3 and deliberately removes
the five P2 response sidecars before requalification. The replacement
qualification then completed atomically and P3
`507cb04c38babcdc0050ddb064007a962efee0a2` publishes the exact five resulting
sidecars.

The earlier `20260815T103924.969402Z` 27/30 rehearsal remains the excluded
diagnostic for the post-DATA terminal-tail stall. The
`20260814T150747.615059Z` 26/30 rehearsal remains the excluded diagnostic for
the pre-header small-response deadlock and compressed-representation variance,
and `20260814T110741.344914Z` remains excluded as well. P2/F2 incorporates the
subsequent receive-credit, FRONT scheduling, and typed-action repairs without
relaxing the acceptance thresholds. Its final images, all 21 campaign
preflights, and the strict four-minute clock gate passed, but the 29/30 result
invalidated that execution lineage. The Q3/F3 replacement qualification,
P3 publication, immutable final images, and exact-21 preflights are now
complete. Formal capture remains blocked because the first P3/F3 strict clock
gate returned `NO_GO` and the passive watch did not converge. After a clean WSL
shutdown/relaunch, it must pass a fresh gate; then the exact image must complete
a new 30/30 rehearsal with a verified interface handoff.

<a id="source-project-history-md-l711"></a>
## Authoritative result contract

Every new run has exactly one active format:

```text
results/<campaign>/<run-id>/
  experiment.json
  evidence.sha256
  inputs/
  samples/
    <workload>/<policy>/visit-000/<defence>/
      capture.pcapng
      neqo/
        run.json
        packets.csv
        events.csv
        schedule.csv
  failures/
  derived/
    summary.csv
    plots/
    report.html
```

`experiment.json` is the sole state and diagnostic record. `evidence.sha256`
covers the authoritative experiment, frozen inputs, accepted samples, and
failed-attempt evidence. `derived/` is excluded from the seal and can be
deleted and regenerated by `analyze` without changing evidence.

There is no capture-result writer for `sample.json`, `fidelity.yml`, JSONL
indexes, resolved-workload duplicates, normalized-trace copies, qlogs, PDFs,
classifiers, datasets, split maps, projections, or secondary checksum formats.
The offline `classifier-pilot` exporter separately produces a create-only,
checksum-closed handoff containing byte-exact raw PCAPNG, classic raw PCAP,
the sealed run receipt, a fixed-identifier/payload-zero stripped PCAP, and a
relative-time/direction/frame-length CSV for every accepted source sample. Raw
captures and run receipts are audit inputs, not classifier features, because
they expose endpoint and protocol identifiers.

The timestamp roots `20260719T141832Z` and `20260731T140827Z` under
`neqo-qcsd-lab/results/` (`results/`) are historical snapshots
from retired writers. They remain useful engineering evidence but are not
accepted by the consolidated commands and must not be presented as current
research results.

<a id="source-project-history-md-l756"></a>
## Completed research-readiness gates

1. Committed the receiver-liveness runtime corrections and updated Neqo gitlink.
2. Regenerated and atomically qualified the exact-six v2 chaff inputs from clean
   images.
3. Verified the frozen 120-sample fitting result and generated the deterministic
   four-file schema-6 bundle.
4. Rebuilt from clean source and verified baked/runtime provenance.
5. Preflighted and ran the checked-in 14-sample external smoke as an independent
   post-fit evaluation.
6. Verified its unchanged evidence seal and generated the exact derived report.
7. Preserved the failed six-workload classifier block as diagnostic evidence
   and stopped before later blocks.
8. Defined the separate advisor-approved five-class rehearsal, 2,500-capture
   acquisition protocol, and schema-v2 offline handoff contract without
   launching traffic.
9. Prepared the final distinct-origin Bootstrap, Cloudflare, Hyper, Serde, and
   RFC 9114 cohort and preserved its historical five-file response-only v1
   qualification transaction for frozen schema-3 compatibility.
10. Preserved the earlier excluded POC5 rehearsal at 26/30, isolated its four
    Hyper/Serde Tamaraw failures to pre-header liveness, and implemented the
    bounded bootstrap and sustained identity-qualification recovery.
11. Preserved the later excluded rehearsal as valid but incomplete at 27/30,
    isolated its three terminal Cloudflare failures to the post-DATA
    terminal-tail path, and committed the bounded bridge in Neqo F1.
12. Built the qualification collection and prepare/actual images from clean
    Q1/F1 source and atomically published the now-superseded five-file v2 cohort:
    every first candidate qualified for 600 stable identity completions in
    total, with a 1,200-byte UDP maximum and no oversized packets.
13. Ran a fresh old-source excluded rehearsal to 30/30 accepted and eligible
    samples and verified its interface handoff.
14. Preserved old-source baseline-01 as complete at 100/100 and paired-01 as a
    valid but incomplete 146/150 diagnostic, then stopped before block 02.
15. Committed acquisition source Q2
    `fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8`, pinning Neqo F2
    `a8378520b9740be782bfe526cdb3eb05e6665571`, and deliberately removed all
    five superseded response-store v2 sidecars before requalification.
16. Built the qualification collection and prepare/actual images from exact
    clean Q2/F2 and atomically qualified the replacement five-file cohort: all
    first candidates produced 600 stable identity completions and 62,007 packet
    observations, with a 1,200-byte UDP maximum and no oversized packets.
17. Published the exact five sidecars without alteration as P2
    `8a8d605166bfc27c6a7b8907162119e055ca7ca2`.
18. Built and independently audited the final collection and prepare images
    from clean P2/F2, recorded their execution implementation aggregate, and
    passed all 21 campaign preflights and deterministic contract tests.
19. Passed the uninterrupted 969-sample cross-clock gate over 241.982 seconds:
    all monotonic/QPC ratios were within `0.9999..1.0001` and the largest
    adjacent realtime-minus-monotonic phase change was 3.001 ms.
20. Preserved the first P2/F2 rehearsal as a valid but incomplete 29/30
    diagnostic, isolated its sole terminal Hyper FRONT failure to runner
    readiness starvation, and stopped before handoff or formal acquisition.
21. Committed the independently audited two-layer starvation repair as Neqo F3
    `6aceaac85243d6e0e34354108e010705d3c83088`, then committed acquisition
    source Q3 `06cacddc21ab0ded9422d445723f60f37c530363` with the superseded
    canonical v2 cohort removed before one new atomic exact-five qualification.
22. Built qualification images from exact clean Q3/F3 and atomically qualified
    all five first candidates for 600 stable identity completions and 61,875
    packet observations, with the required inter-epoch gaps, a 1,200-byte UDP
    maximum, and no oversized packets.
23. Published the untouched qualification output as P3
    `507cb04c38babcdc0050ddb064007a962efee0a2`, built and independently audited
    the immutable final P3/F3 images, and passed all 21 exact campaign
    preflights plus 72/72 focused deterministic contract tests.
24. Stopped before rehearsal when the first 969-sample P3/F3 strict clock gate
    returned `NO_GO`; preserved the sample digest and completed a read-only
    settle watch that found no convergence, without changing the clock or time
    services.
25. Froze the conditional WSL-status interpretation and rolling 30-second rate
    checks before a separate official gate, then stopped again when that gate
    returned `NO_GO`; preserved digest
    `af495806f5777c06e95e18c1f7d64ef654852f84b5af132684cf0b3b52fc0d1c`
    and launched no rehearsal or capture traffic.

<a id="source-project-history-md-l830"></a>
## Future operational gates

1. Run a new uninterrupted 969-sample strict cross-clock gate for the exact
   final P3/F3 lineage under the already declared WSL status interpretation
   above. Do not launch traffic unless every unchanged quantitative and rolling
   bound and both endpoint-status checks pass.
2. Run and verify only `classifier-poc5-rehearsal.yml`; export to the reserved
   create-only `classifier-poc5-rehearsal-v2-p-507cb04c38ba` destination and
   verify its interface package. Continue only if exactly 30/30 samples are
   accepted and eligible and the receiver confirms the handoff interface.
   Permanently exclude all rehearsal captures from classifier training and
   evaluation.
3. Restart formal acquisition from baseline-01 and capture blocks 01--10 in
   exact chronological order, alternating baseline-first and paired-first as
   declared, verifying and sealing every result before the next block.
4. Export the exact 20-result schema-v2 corpus to the reserved create-only
   `classifier-poc5-v2-p-507cb04c38ba` destination in canonical argument order
   `baseline-01, paired-01, ..., baseline-10, paired-10`, verify it, and hand it
   to the classifier workflow. Sealed timestamps must retain the odd
   baseline-first/even paired-first acquisition chronology, and all formal
   results must retain one identical clean Lab/Neqo/image source receipt.

The rehearsal authorizes only the exact clean image, workload bytes, and
campaign commit it exercised. Any rebuild, source/workload repair, parameter
change, or class substitution invalidates that authorization and requires a
new excluded rehearsal before formal acquisition. The historical 42/126
engineering campaigns remain outside this protocol and must not be launched.

---

<a id="source-project-history-md-l860"></a>
## Historical continuation after the frozen snapshot

The entries below extend the chronology. They do not alter the original
2026-08-18 body above and do not supersede current Git source, immutable
executed receipts, or a verified attestation.

<a id="source-project-history-md-l866"></a>
## 2026-08-19 to 2026-08-21 — sealed multi-origin classifier corpus

The fresh `classifier-multiorigin5-v2` lineage replaced the earlier
single-origin POC acquisition without reusing its captures, seeds, sample
identifiers, qualification sidecars, campaign namespaces, or handoff rows. An
excluded 30-sample rehearsal first completed and was exported separately for
interface verification. Formal acquisition then ran as twenty sealed campaigns
over ten temporal blocks from `2026-08-19T13:40:49Z` to
`2026-08-21T07:36:29Z`.

All 2,500 planned formal samples were accepted and eligible:

| Condition | Samples | Role |
|---|---:|---|
| Undefended | 1,500 | 1,200 train, 150 validation, 150 held-out test |
| FRONT | 500 | Inference-only transfer evaluation |
| Tamaraw | 500 | Inference-only transfer evaluation |

Each of the five classes contributes exactly 500 samples. The source lineage is
clean Lab `8988a48a8e43cc9d47505cae12ee7758bc7fa5ee`, clean Neqo
`6aceaac85243d6e0e34354108e010705d3c83088`, and collection image
`sha256:38c24b0c5c4a06b223a904e896e1e38401c78fffbe6edab0f17846bb66a04de2`.

The create-only formal handoff (`handoffs/classifier-multiorigin5-v2/`)
contains 12,504 regular files: 2,500 raw PCAPNG files, 2,500 classic raw PCAP
files, 2,500 raw run receipts, 2,500 identifier-free shape PCAPs, 2,500 CSV
traces, and four top-level inventory files. Its
dataset receipt (`handoffs/classifier-multiorigin5-v2/dataset.json`)
records the exact class, condition, split, observer, privacy, and source-result
bindings. `SHA256SUMS` governs the other 12,503 files and hashes to
`85bfd88be6c2105201ec7ff3eb87a743e378bd748a9c2097db2fb227875ec2d7`.

This corpus is immutable historical evidence. The later BuFLO study has a
separate qualification set, campaign namespace, handoff, and evaluator, and
binds the classifier handoff's three top-level hashes before and after formal
capture to prove it was not modified.

<a id="source-project-history-md-l903"></a>
## 2026-08-27 to 2026-08-28 — BuFLO and CS-BuFLO candidate development

Rust commit `b52fe4e9696b07f0e5f1ce12b58a919174342b95` introduced
independent client-only BuFLO and CS-BuFLO adaptations. Lab commit
`160762ef8cf505bb7a15f5532ffb33bc77467661` added the isolated reference
oracle, parameter receipts, nine-mode regression, controlled-network
qualification, public smoke and rehearsal, focused formal campaign, exporter,
evaluator, and fail-closed attestation workflow.

Cohort numbers are create-only execution-lineage identifiers, not semantic
software releases. A later source, parameter, workload, chaff, or
acceptance-rule change cannot reuse an earlier cohort's admission evidence.
Missing cohort numbers and versions with no terminal receipt are preserved
development attempts, not scientific results.

| Cohorts | Principal progression | Preserved live evidence | Disposition |
|---|---|---|---|
| v1–v4 | Initial implementation, portable build receipts, installed qualification entry point, and local regression preparation. | Clean build receipts exist for v1–v4; every preserved reference receipt from v2 onward passed. No terminal live matrix admitted the candidates. | Development-only. |
| v5–v7 | Endpoint tests, qualification evidence, and deterministic Latin-square ordering were refined. v5 produced no immutable build receipt. | v7's first indexed established-mode regression accepted 10/14 samples. | Retired diagnostic lineage. |
| v8–v12 | Parser-credit ownership, strict lint declarations, and exact client scheduling were integrated. v11 produced no immutable build receipt. | v8, v10, and v12 preserved the established seven modes at 14/14, while the two BuFLO samples remained 0/2. | Established-mode non-regression evidence only; candidate gate failed. |
| v13–v15 | Candidate evidence schemas, terminal-state accounting, local CS-BuFLO handoff, output composition fidelity, and exact BuFLO release dispatch were hardened. | The established seven remained 14/14. BuFLO progressed from 0/2 in v13 to 1/2 in v14; v15 created build/reference receipts but no terminal regression index. | Retired diagnostic lineages. |
| v16–v17 | Controlled-network evidence and exact incoming-opportunity timing were added. | v16 reached BuFLO 2/2 and established modes 14/14, while CS-BuFLO remained 0/2. v17 was the first 18/18 nine-mode regression and also completed the clean controlled shard at 40/40. | V17 passed its exercised clean shard, but later source changes prevent its reuse as current qualification evidence. |
| v18–v20 | CS-BuFLO stop-then-drain accounting, complex drain receipts, strict Rust lint evidence, exact code-gate sidecars, and in-image Git provenance were completed. | v18, v19, and v20 each completed the 18/18 regression. v20 additionally produced the first complete typed code-gate receipt. | V20 is the last complete immutable predecessor gate, but its controlled shard failed and its source is now superseded. |

Every preserved reference execution from v2 through v20 reproduced all eight
BuFLO source-compatible profiles and passed the CS-BuFLO author-source and
archive checks. Repetition across cohorts demonstrates oracle stability; it
does not permit reference evidence from one source lineage to authorise
another.

<a id="source-project-history-md-l933"></a>
## 2026-08-28 — v20 reference, code, regression, and controlled result

Cohort v20 binds clean Lab
`0a53d0ab4cceab4d61efee5dc16a37071d9511c9`, clean Neqo
`be13aa1e549a037ffcd1bc7ccedcb8b9edf9bb8a`, and collection image
`sha256:d048c3fc2262a4d9443b09d96dfd1adc1287556cacae6b6bb7738b759dbad582`.

The v20 reference receipt (`artifacts/buflo-study/reference-execution-v20.json`)
passed:

- exact execution of all eight source-compatible BuFLO configurations;
- the pinned CS-BuFLO author-source slices;
- the 4,000-record CPSP archive audit, including 3,824 non-zero-baseline records
  and reproduced aggregate ratio `2.282792444255336`;
- isolated, read-only reference inputs with no author code in the ordinary
  collection image.

The v20 code-gate receipt (`artifacts/buflo-study/code-gate-v20.json`)
passed the complete declared Rust format, test, and strict Clippy commands; the
full Lab suite reported 1,071 passed and five skipped; the focused candidate
schema/handoff suite reported 242 passed and two skipped; and the live
regression accepted all 18 planned samples. Its established-seven oracle also
confirmed that the pre-existing seven selectable modes retained their frozen
configurations and behaviour.

The controlled campaign did not pass. Only the 40-sample clean shard ran; the
remaining three network profiles were never started. Its
sealed checkpoint (`results/buflo-study-controlled-v20/results/buflo-study-v1-controlled-00-1200/20260827T193534.561744Z/experiment.json`)
records 39 accepted and eligible samples and one terminally failed
`local-large`, visit-3 BuFLO sample after its three permitted attempts.

The failed attempt retained zero BuFLO partial, suppressed, missed, catch-up,
or unresolved cells, but one incoming scheduled-credit advertisement was
observed 9,150 µs after its action boundary, outside the strict 5,000 µs
realisation window. The fidelity gate correctly rejected the sample instead of
treating the late credit as satisfied or catching it up. Consequently v20
produced neither a 160/160 controlled qualification receipt nor authority for
smoke, rehearsal, or formal capture.

<a id="source-project-history-md-l972"></a>
## 2026-08-28 — post-v20 correction and non-evidentiary v21/v22 attempts

The v20 failure led to a narrow cross-endpoint timing correction. Rust commits
`11955a286e86213d9c0d026597b482fa2e05215d` and
`9dc0e005d14b26b7e9b49408787eb444d35f0a32` restrict the post-outgoing drive
to endpoints that still own accepted, unadvertised scheduled receive credit,
give each such endpoint an immediate packet-build opportunity within the exact
window, avoid driving already-composed same-endpoint control twice, and retain
a typed deadline failure when credit remains unadvertised. Lab commits
`665f3ec26529da7a1996b1fdfa7a8ed00907c2cc` and
`064919238765802caaf182ff069e711a7d4a4b54` version the corresponding timing
evidence and pin complete endpoint selection.

These changes were committed at clean source heads, and focused plus full Rust
checks passed during engineering verification. They are not yet live
qualification evidence: no immutable post-fix build, reference, regression,
controlled, or code-gate receipt exists.

Cohort v21 was retired when its clean build exposed a deterministic Rust
predicate gap before a terminal create-only receipt could be published. After
that correction, cohort v22's collection build completed its Rust gates and
release binaries, but the subsequent no-cache reference-image build was
interrupted by Docker Desktop storage failure: the Docker data VHD produced
`SIGBUS`, followed by `/dev/sdf` input/output errors. No v21 or v22
build-execution receipt, reference receipt, capture admission, or sample result
was created. Their console outcomes are diagnostic engineering observations
only and cannot be cited as passed study gates.

The storage failure did not alter the sealed classifier corpus or any earlier
immutable cohort. It did require retiring v22 rather than resuming or
reconstructing a partial receipt.

<a id="source-project-history-md-l1004"></a>
## Next planned lineage — v23

After a full WSL shutdown/relaunch and confirmed Docker storage health, cohort
v23 will start from the exact clean Lab and Neqo heads above. It will not
inherit v17's 40/40 clean shard, v20's 39/40 shard, or any unreceipted v21/v22
outcome.

The v23 order is:

1. build all pinned collection, preparation, and isolated-reference images
   with pull and no cache, then publish one immutable build-execution receipt;
2. execute and seal the independent reference gate;
3. rerun the complete 18-sample nine-mode regression and the complete
   160-sample four-profile controlled matrix;
4. publish qualification and code-gate receipts only if every required sample
   and command passes;
5. proceed, without source or parameter changes, through 20/20 public smoke,
   40/40 public rehearsal, cohort freeze, and the 1,500-sample focused formal
   study;
6. export and evaluate the sealed formal results, complete the original-study
   comparison review, and generate a validation attestation only if every
   preceding hash and gate verifies.

Until that attestation exists, the correct project status remains **five
validated research defences plus two candidates**, with nine selectable modes
in total.
